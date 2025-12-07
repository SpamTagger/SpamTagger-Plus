#!/usr/bin/env perl
#
# SpamTagger Plus - Open Source Spam Filtering
# Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
# Copyright (C) 2025 John Mertz <git@john.me.tz>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#
# This script will dump the firewall script
#
# Usage:
#  dump_firewall.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use Net::DNS();
use DBI();
use ReadConfig();
use GetDNS();
our $dns = GetDNS->new();

our $config = ReadConfig::get_instance();
our $VARDIR = $config->get_option('VARDIR');

my $DEBUG = 1;

my $start_script = $config->get_option('SRCDIR')."/etc/firewall/start";
my $stop_script = $config->get_option('SRCDIR')."/etc/firewall/stop";
my %services = (
  'web' => ['80|443', 'TCP'],
  'mariadb' => ['3306:3307', 'TCP'],
  'snmp' => ['161', 'UDP'],
  'ssh' => ['22', 'TCP'],
  'mail' => ['25', 'TCP'],
  'soap' => ['5132', 'TCP']
);
our %fail2ban_sets = ('st-exim' => 'mail', 'st-ssh' => 'ssh', 'st-webauth' => 'web');
my $iptables = "/sbin/iptables";
my $ip6tables = "/sbin/ip6tables";
my $ipset_bin = "/sbin/ipset";

my $lasterror = "";
my $has_ipv6 = 0;

unlink($start_script);
unlink($stop_script);

my $dbh;
$dbh = DBI->connect(
  "DBI:mariadb:database=st_config;host=localhost;mariadb_socket=".$config->get_option('VARDIR')."/run/mariadb_replica/mariadbd.sock",
  "spamtagger",
  $config->get_option('MYSPAMTAGGERPWD'),
  {RaiseError => 0, PrintError => 0}
) or fatal_error("CANNOTCONNECTDB", $dbh->errstr);

my %sources_replicas = get_sources_replicas();

my %trustedips = ( '127.0.0.1' => 1 );
foreach (keys(%sources_replicas)) {
  if ($_ =~ m/\d+\.\d+\.\d+\.\d+/) {
    $trustedips{$_} = 1;
  } elsif ($_ =~ m/\d+::?+\d/) {
    $trustedips{$_} = 1;
  } else {
    my @a = $dns->get_a($_);
    if (scalar(@a)) {
      $trustedips{$_} = 1 foreach (@a);
    }
  }
}
our $trusted = join(' ', keys(%trustedips));

my $dnsres = Net::DNS::Resolver->new;

# do we have ipv6 ?
my $interfaces;
if (open($interfaces, '<', '/etc/network/interfaces')) {
  while (<$interfaces>) {
    if ($_ =~ m/iface \S+ inet6/) {
      $has_ipv6 = 1;
      last;
    }
  }
  close($interfaces);
}


my %rules;
get_default_rules();
get_external_rules();
get_api_rules();

do_start_script() or fatal_error("CANNOTDUMPMYSQLFILE", $lasterror);;
do_stop_script();

print "DUMPSUCCESSFUL";

############################
sub get_sources_replicas {
  my %hosts;

  my $sth = $dbh->prepare("SELECT hostname from source");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  while (my $ref = $sth->fetchrow_hashref() ) {
    $hosts{$ref->{'hostname'}} = 1;
  }
  $sth->finish();

  $sth = $dbh->prepare("SELECT hostname from replica");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  while (my $ref = $sth->fetchrow_hashref() ) {
    $hosts{$ref->{'hostname'}} = 1;
  }
  $sth->finish();
  return %hosts;

}

sub get_default_rules {
  foreach my $host (keys %sources_replicas) {
    next if ($host =~ /127\.0\.0\.1/ || $host =~ /^\:\:1$/);

    $rules{"$host mariadb TCP"} = [ $services{'mariadb'}[0], $services{'mariadb'}[1], $host];
    $rules{"$host snmp UDP"} = [ $services{'snmp'}[0], $services{'snmp'}[1], $host];
    $rules{"$host ssh TCP"} = [ $services{'ssh'}[0], $services{'ssh'}[1], $host];
    $rules{"$host soap TCP"} = [ $services{'soap'}[0], $services{'soap'}[1], $host];
  }
  my @subs = get_subnets();
  foreach my $sub (@subs) {
    $rules{"$sub ssh TCP"} = [ $services{'ssh'}[0], $services{'ssh'}[1], $sub ];
  }
  return;
}

sub get_api_rules {
  my $sth = $dbh->prepare("SELECT api_admin_ips, api_fulladmin_ips FROM system_conf");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);
  my %ips;
  while (my $ref = $sth->fetchrow_hashref() ) {
    my @notempty;
    push (@notempty, $ref->{'api_admin_ips'}) if (defined($ref->{'api_admin_ips'}) && $ref->{'api_admin_ips'} ne '');
    push (@notempty, $ref->{'api_fulladmin_ips'}) if (defined($ref->{'api_fulladmin_ips'}) && $ref->{'api_fulladmin_ips'} ne '');
    foreach my $ip (expand_host_string(my $string = join("\n", @notempty),{'dumper'=>'system_conf/api_admin_ips'})) {
      $ips{$ip} = 1;
    }
  }
  $ips{$_} = 1 foreach (get_subnets());
  foreach my $ip (keys %ips) {
    $rules{$ip." soap TCP"} = [ $services{'soap'}[0], $services{'soap'}[1], $ip ];
  }
  return;
}

sub get_external_rules {
  my $sth = $dbh->prepare("SELECT service, port, protocol, allowed_ip FROM external_access");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  while (my $ref = $sth->fetchrow_hashref() ) {
    #next if ($ref->{'allowed_ip'} !~ /^(\d+.){3}\d+\/?\d*$/);
    next if ($ref->{'port'} !~ /^\d+[\:\|]?\d*$/);
    next if ($ref->{'protocol'} !~ /^(TCP|UDP|ICMP)$/i);
    foreach my $ip (expand_host_string($ref->{'allowed_ip'},{'dumper'=>'snmp/allowedip'})) {
      # IPs already validated and converted to CIDR in expand_host_string, just remove non-CIDR entries
      if ($ip =~ m#/\d+$#) {
        $rules{$ip." ".$ref->{'service'}." ".$ref->{'protocol'}} = [ $ref->{'port'}, $ref->{'protocol'}, $ip];
      }
    }
  }

  ## check snmp UDP
  foreach my $rulename (keys %rules) {
    if ($rulename =~ m/([^,]+) snmp/) {
      $rules{$1." snmp UDP"} = [ 161, 'UDP', $rules{$rulename}[2]];
    }
  }

  ## enable submission port
  foreach my $rulename (keys %rules) {
    if ($rulename =~ m/([^,]+) mail/) {
      $rules{$1." submission TCP"} = [ 587, 'TCP', $rules{$rulename}[2]];
    }
  }

  ## do we need obsolete SMTP SSL port ?
  $sth = $dbh->prepare("SELECT tls_use_ssmtp_port FROM mta_config where stage=1");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);
  while (my $ref = $sth->fetchrow_hashref() ) {
    if ($ref->{'tls_use_ssmtp_port'} > 0) {
      foreach my $rulename (keys %rules) {
        if ($rulename =~ m/([^,]+) mail/) {
          $rules{$1." smtps TCP"} = [ 465, 'TCP', $rules{$rulename}[2] ];
        }
      }
    }
  }
  return;
}

sub do_start_script {
  my $START;
  unless (open($START, ">", $start_script) ) {
     $lasterror = "Cannot open start script";
     return 0;
  }

  print $START "#!/bin/sh\n";

  print $START "/sbin/modprobe ip_tables\n";
  if ($has_ipv6) {
    print $START "/sbin/modprobe ip6_tables\n";
  }

  print $START "\n# policies\n";
  print $START $iptables." -P INPUT DROP\n";
  print $START $iptables." -P FORWARD DROP\n";
  if ($has_ipv6) {
    print $START $ip6tables." -P INPUT DROP\n";
    print $START $ip6tables." -P FORWARD DROP\n";
  }

  print $START "\n# bad packets:\n";
  print $START $iptables." -A INPUT -p tcp ! --syn -m state --state NEW -j DROP\n";
  if ($has_ipv6) {
    print $START $ip6tables." -A INPUT -p tcp ! --syn -m state --state NEW -j DROP\n";
  }

  print $START "# local interface\n";
  print $START $iptables." -A INPUT -p ALL -i lo -j ACCEPT\n";
  if ($has_ipv6) {
    print $START $ip6tables." -A INPUT -p ALL -i lo -j ACCEPT\n";
  }

  print $START "# accept\n";
  print $START $iptables." -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
  if ($has_ipv6) {
    print $START $ip6tables." -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
  }

  print $START $iptables." -A INPUT -p ICMP --icmp-type 8 -j ACCEPT\n";
  if ($has_ipv6) {
    print $START $ip6tables." -A INPUT -p ipv6-icmp -j ACCEPT\n";
  }

  my $globals = {
    '4' => {},
    '6' => {}
  };
  foreach my $description (sort keys %rules) {
    my @ports = split '\|', $rules{$description}[0];
    my @protocols = split '\|', $rules{$description}[1];
    foreach my $port (@ports) {
      foreach my $protocol (@protocols) {
        my $host = $rules{$description}[2];
        # Globals
        if ($host eq '0.0.0.0/0' || $host eq '::/0') {
          next if ($globals->{'4'}->{$port}->{$protocol});
          print $START "\n# $description\n";
          print $START $iptables." -A INPUT -p ".$protocol." --dport ".$port." -j ACCEPT\n";
          $globals->{'4'}->{$port}->{$protocol} = 1;
          if ($has_ipv6) {
            $globals->{'6'}->{$port}->{$protocol} = 1;
            print $START $ip6tables." -A INPUT -p ".$protocol." --dport ".$port." -j ACCEPT\n";
          }
        # IPv6
        } elsif ($host =~ m/\:/) {
          next unless ($has_ipv6);
          next if ($globals->{'6'}->{$port}->{$protocol});
          print $START "\n# $description\n";
          print $START $ip6tables." -A INPUT -p ".$protocol." --dport ".$port." -s ".$host." -j ACCEPT\n";
        # IPv4
        } elsif ($host =~ m/^(\d+\.){3}\d+(\/\d+)?$/) {
          next if ($globals->{'4'}->{$port}->{$protocol});
          print $START "\n# $description\n";
          print $START $iptables." -A INPUT -p ".$protocol." --dport ".$port." -s ".$host." -j ACCEPT\n";
        # Hostname
        } else {
          next if ($globals->{'4'}->{$port}->{$protocol});
          print $START "\n# $description\n";
          print $START $iptables." -A INPUT -p ".$protocol." --dport ".$port." -s ".$host." -j ACCEPT\n";
          if ($has_ipv6) {
            my $reply = $dnsres->query($host, "AAAA");
            if ($reply) {
              print $START $ip6tables." -A INPUT -p ".$protocol." --dport ".$port." -s ".$host." -j ACCEPT\n";
            }
          }
        }
      }
    }
  }

  my $existing = {};
  my $sets_raw = `ipset list`;
  my $ipset = '';
  my $members = 0;
  foreach (split(/\n/, $sets_raw)) {
    if ($_ =~ m/^Name: (.*)$/) {
      $ipset = $1;
      $existing->{$ipset} = {};
      $members = 0;
      next;
    }
    unless ($members) {
      if ($_ =~ m/Members:/) {
        $members = 1 if ($ipset =~ /BLOCKLIST(IP|NET)/);
        next;
      } else {
        next;
      }
    }
    next if ($_ =~ /^\s*$/);
    $existing->{$ipset}->{$_} = 1;
  }

  my @blocklist_files = ('/usr/spamtagger/etc/firewall/blocklist.txt', '/usr/spamtagger/etc/firewall/blocklist_custom.txt');
  my $blocklist_script = '/usr/spamtagger/etc/firewall/blocklist';
  unlink $blocklist_script;
  my $BLOCKLIST;
  open($BLOCKLIST, '>>', $blocklist_script);
  print $BLOCKLIST "#! /bin/sh\n\n";
  print $BLOCKLIST "$ipset_bin create BLOCKLISTIP hash:ip\n" unless (defined($existing->{'BLOCKLISTIP'}));
  print $BLOCKLIST "$ipset_bin create BLOCKLISTNET hash:net\n" unless (defined($existing->{'BLOCKLISTNET'}));
  foreach my $period (qw( bl 1d 1w 1m 1y )) {
    foreach my $f2b (keys(%fail2ban_sets)) {
      print $BLOCKLIST "$ipset_bin create $f2b-$period hash:ip\n" unless (defined($existing->{"$f2b-$period"}));
    }
  }
  foreach my $blocklist_file (@blocklist_files) {
    if ( -e $blocklist_file ) {
      my $BLOCK_IP;
      if (open($BLOCK_IP, '<', $blocklist_file) ) {
        while (my $IP = <$BLOCK_IP>) {
          chomp($IP);
          if ($IP =~ m#/\d+$#) {
            if ($existing->{'BLOCKLISTNET'}->{$IP}) {
              delete($existing->{'BLOCKLISTNET'}->{$IP});
            } else {
              print $BLOCKLIST "$ipset_bin add BLOCKLISTNET $IP\n";
            }
          } else {
            if ($existing->{'BLOCKLISTIP'}->{$IP}) {
              delete($existing->{'BLOCKLISTIP'}->{$IP});
            } else {
              print $BLOCKLIST "$ipset_bin add BLOCKLISTIP $IP\n";
            }
          }
        }
        close $BLOCK_IP;
      }
    }
  }
  my $remove = '';
  foreach my $list (keys(%{$existing})) {
    $remove .= "$ipset_bin del $list $_\n" foreach (keys(%{$existing->{$list}}));
  }
  print $BLOCKLIST "\n# Cleaning up removed IPs:\n$remove\n" if ($remove ne '');
  foreach my $period (qw( bl 1d 1w 1m 1y )) {
    foreach my $f2b (keys(%fail2ban_sets)) {
      my $ports = $services{$fail2ban_sets{$f2b}}[0];
      $ports =~ s/[:|]/,/;
      print $BLOCKLIST "$iptables -I INPUT -p ".lc($services{$fail2ban_sets{$f2b}}[1])." ".($ports =~ m/,/ ? '-m multiport --dports' : '--dport')." $ports -m set --match-set $f2b-$period src -j REJECT\n";
      print $BLOCKLIST "$iptables -I INPUT -p ".lc($services{$fail2ban_sets{$f2b}}[1])." ".($ports =~ m/,/ ? '-m multiport --dports' : '--dport')." $ports -m set --match-set $f2b-$period src -j LOG\n";
    }
  }
  foreach ( qw( BLOCKLISTIP BLOCKLISTNET ) ) {
    print $BLOCKLIST "$iptables -I INPUT -m set --match-set $_ src -j REJECT\n";
    print $BLOCKLIST "$iptables -I INPUT -m set --match-set $_ src -j LOG\n\n";
  }
  chmod 0755, $blocklist_script; ## no critic (leading zero octal notation)
  print $START "\n$blocklist_script\n";
  close $BLOCKLIST;
  close $START;

  chmod 0755, $start_script; ## no critic (leading zero octal notation)
  return;
}

sub do_stop_script {
  my $STOP;
  unless (open($STOP, ">", $stop_script) ) {
    $lasterror = "Cannot open stop script";
    return 0;
  }

  print $STOP "#!/bin/sh\n";

  print $STOP $iptables." -P INPUT ACCEPT\n";
  print $STOP $iptables." -P FORWARD ACCEPT\n";
  print $STOP $iptables." -P OUTPUT ACCEPT\n";
  if ($has_ipv6) {
    print $STOP $ip6tables." -P INPUT ACCEPT\n";
    print $STOP $ip6tables." -P FORWARD ACCEPT\n";
    print $STOP $ip6tables." -P OUTPUT ACCEPT\n";
  }

  print $STOP $iptables." -F\n";
  print $STOP $iptables." -X\n";
  if ($has_ipv6) {
    print $STOP $ip6tables." -F\n";
    print $STOP $ip6tables." -X\n";
  }

  close $STOP;
  chmod 0755, $stop_script; ## no critic (leading zero octal notation)
  return;
}

sub get_subnets {
  my $ifconfig = `/sbin/ifconfig`;
  my @subs = ();
  foreach my $line (split("\n", $ifconfig)) {
    if ($line =~ m/\s+inet\ addr:([0-9.]+)\s+Bcast:[0-9.]+\s+Mask:([0-9.]+)/) {
      my $ip = $1;
      my $mask = $2;
      if ($mask && $mask =~ m/\d/) {
        my $ipcalc = `/usr/bin/ipcalc $ip $mask`;
        foreach my $subline (split("\n", $ipcalc)) {
           if ($subline =~ m/Network:\s+([0-9.]+\/\d+)/) {
            push @subs, $1;
           }
        }
      }
    }
  }
  return @subs;
}

#############################
sub dump_local_file ($template, $target) {
  my $tmp;
  if (open($tmp, '<', $template)) {
    my $output = "";
    $output .= $_ while (<$tmp>);
    $output =~ s/__TRUSTEDIPS__/$trusted/g;
    my $out;
    if (open($out, '>', $target)) {
      print $out $output;
    } else {
      print STDERR "Failed to open target $target\n";
    }
  } else {
    print STDERR "Failed to open template $template\n";
  }
  return;
}

sub fatal_error ($msg, $full) {
  print $msg;
  print "\n Full information: $full \n" if ($DEBUG);
  exit(0);
}

sub expand_host_string ($string, $args = {}) {
  return $dns->dumper($string,$args);
}
