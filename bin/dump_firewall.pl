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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
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
#   dump_firewall.pl


use v5.40;
use strict;
use warnings;
use utf8;
use Carp qw( confess );

my ($conf, $SRCDIR);
BEGIN {
    if ($0 =~ m/(\S*)\/\S+.pl$/) {
        my $path = $1."/../lib";
        unshift (@INC, $path);
    }
    require ReadConfig;
    $conf = ReadConfig::get_instance();
    $SRCDIR = $conf->get_option('SRCDIR') || '/usr/spamtagger';
}

use STUtils qw(open_as rmrf);

use Net::DNS;
require GetDNS;
our $dns = GetDNS->new();
require DB;

my $DEBUG = 1;

my %services = (
    'web' => ['80|443', 'TCP'],
    'mariadb' => ['3306:3307', 'TCP'],
    'snmp' => ['161', 'UDP'],
    'ssh' => ['22', 'TCP'],
    'mail' => ['25', 'TCP'],
    'soap' => ['5132', 'TCP']
);
my %ufw = (
    'exim_stage1' => {
        'port' => 2500,
        'dnat' => 25,
    },
    'exim_stage2' => {
        'port' => 2424,
    },
    'exim_stage4' => {
        'port' => 2525,
    }
);
foreach my $key (keys(%ufw)) {
    if (-e '/etc/ufw/applications.d/'.$key) {
        if (-l '/etc/ufw/applications.d/'.$key) {
            next if (readlink('/etc/ufw/applications.d/'.$key) eq $SRCDIR.'/etc/ufw/'.$key);
        }
        rmrf('/etc/ufw/applications.d/'.$key);
    }
    symlink($SRCDIR.'/etc/ufw/'.$key, '/etc/ufw/applications.d/'.$key)
}
our %fail2ban_sets = ('mc-exim' => 'mail', 'mc-ssh' => 'ssh', 'mc-webauth' => 'web');
our $iptables = "/usr/sbin/iptables";
our $ip6tables = "/usr/sbin/ip6tables";
our $ipset = "/usr/sbin/ipset";

my $has_ipv6 = 0;

my $dbh = DB->db_connect('replica', 'st_config');

my %sources_replicas = get_sources_replicas();

my $dnsres = Net::DNS::Resolver->new;

# do we have ipv6 ?
if (open(my $interfaces, '<', '/etc/network/interfaces')) {
    while (<$interfaces>) {
        if ($_ =~ m/iface \S+ inet6/) {
            $has_ipv6 = 1;
            last;
        }
    }
    close($interfaces);
}

symlink($SRCDIR.'/etc/apparmor', '/etc/apparmor.d/spamtagger') unless (-e '/etc/apparmor.d/spamtagger');

my %rules;
get_default_rules(\%rules);
get_external_rules(\%rules);
get_api_rules(\%rules);
do_start_script(\%rules);
do_stop_script(\%rules);

############################
sub get_sources_replicas()
{
    my %hosts;

    my $sth = $dbh->prepare("SELECT hostname from source");
    confess("CANNOTEXECUTEQUERY $dbh->errstr") unless $sth->execute();

    while (my $ref = $sth->fetchrow_hashref() ) {
         $hosts{$ref->{'hostname'}} = 1;
    }
    $sth->finish();

    $sth = $dbh->prepare("SELECT hostname from replica");
    confess("CANNOTEXECUTEQUERY $dbh->errstr") unless $sth->execute();

    while (my $ref = $sth->fetchrow_hashref() ) {
        $hosts{$ref->{'hostname'}} = 1;
    }
    $sth->finish();
    return %hosts;

}

sub get_default_rules($rules)
{
    foreach my $host (keys %sources_replicas) {
        next if ($host =~ /127\.0\.0\.1/ || $host =~ /^\:\:1$/);

        $rules->{"$host mariadb TCP"} = [ $services{'mariadb'}[0], $services{'mariadb'}[1], $host];
        $rules->{"$host snmp UDP"} = [ $services{'snmp'}[0], $services{'snmp'}[1], $host];
        $rules->{"$host ssh TCP"} = [ $services{'ssh'}[0], $services{'ssh'}[1], $host];
        $rules->{"$host soap TCP"} = [ $services{'soap'}[0], $services{'soap'}[1], $host];
    }
    my @subs = getSubnets();
    foreach my $sub (@subs) {
        $rules->{"$sub ssh TCP"} = [ $services{'ssh'}[0], $services{'ssh'}[1], $sub ];
    }
}

sub get_api_rules($rules)
{
    my $sth = $dbh->prepare("SELECT api_admin_ips, api_fulladmin_ips FROM system_conf");
    $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);
    my %ips;
    while (my $ref = $sth->fetchrow_hashref() ) {
        my @notempty;
        push (@notempty, $ref->{'api_admin_ips'}) if (defined($ref->{'api_admin_ips'}) && $ref->{'api_admin_ips'} != '');
        push (@notempty, $ref->{'api_fulladmin_ips'}) if (defined($ref->{'api_fulladmin_ips'}) && $ref->{'api_fulladmin_ips'} != '');
        foreach my $ip (expand_host_string(my $string = join("\n", @notempty),('dumper'=>'system_conf/api_admin_ips'))) {
            $ips{$ip} = 1;
        }
    }
    $ips{$_} = 1 foreach (getSubnets());
    foreach my $ip (keys %ips) {
        $rules{$ip." soap TCP"} = [ $services{'soap'}[0], $services{'soap'}[1], $ip ];
    }
}

sub get_external_rules($rules)
{
    my $sth = $dbh->prepare("SELECT service, port, protocol, allowed_ip FROM external_access");
    confess("CANNOTEXECUTEQUERY $dbh->errstr") unless $sth->execute();

    while (my $ref = $sth->fetchrow_hashref() ) {
         #next if ($ref->{'allowed_ip'} !~ /^(\d+.){3}\d+\/?\d*$/);
         next if ($ref->{'port'} !~ /^\d+[\:\|]?\d*$/);
         next if ($ref->{'protocol'} !~ /^(TCP|UDP|ICMP)$/i);
         foreach my $ip (expand_host_string($ref->{'allowed_ip'},('dumper'=>'snmp/allowedip'))) {
             # IPs already validated and converted to CIDR in expand_host_string, just remove non-CIDR entries
             if ($ip =~ m#/\d+$#) {
                 $rules->{$ip." ".$ref->{'service'}." ".$ref->{'protocol'}} = [ $ref->{'port'}, $ref->{'protocol'}, $ip];
             }
         }
    }

    ## check snmp UDP
    foreach my $rulename (keys %rules) {
        if ($rulename =~ m/([^,]+) snmp/) {
            $rules->{$1." snmp UDP"} = [ 161, 'UDP', $rules->{$rulename}[2]];
        }
    }

    ## enable submission port
    foreach my $rulename (keys %rules) {
        if ($rulename =~ m/([^,]+) mail/) {
            $rules->{$1." submission TCP"} = [ 587, 'TCP', $rules->{$rulename}[2]];
        }
    }
    ## do we need obsolete SMTP SSL port ?
    $sth = $dbh->prepare("SELECT tls_use_ssmtp_port FROM mta_config where stage=1");
    confess("CANNOTEXECUTEQUERY $dbh->errstr") unless $sth->execute();
    while (my $ref = $sth->fetchrow_hashref() ) {
        if ($ref->{'tls_use_ssmtp_port'} > 0) {
            foreach my $rulename (keys %rules) {
                if ($rulename =~ m/([^,]+) mail/) {
                    $rules->{$1." smtps TCP"} = [ 465, 'TCP', $rules->{$rulename}[2] ];
                }
            }
        }
    }
}

sub do_start_script($rules)
{
    my %rules = %{$rules};
    my $start_script = "${SRCDIR}/etc/firewall/start";
    unlink($start_script);

    my $START;
    confess "Cannot open $start_script" unless ( $START = ${open_as($start_script)} );

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
                # globals
                if ($host eq '0.0.0.0/0' || $host eq '::/0') {
                    next if ($globals->{'4'}->{$port}->{$protocol});
                    print $START "\n# $description\n";
                    print $START $iptables." -A INPUT -p ".$protocol." --dport ".$port." -j ACCEPT\n";
                    $globals->{'4'}->{$port}->{$protocol} = 1;
                    if ($has_ipv6) {
                        print $START $ip6tables." -A INPUT -p ".$protocol." --dport ".$port." -j ACCEPT\n";
                        $globals->{'6'}->{$port}->{$protocol} = 1;
                    }
                # IPv6
                } elsif ($host =~ m/\:/) {
                    next unless ($has_ipv6);
                    next if ($globals->{'6'}->{$port}->{$protocol});
                    print $START "\n# $description\n";
                    print $START $ip6tables." -A INPUT -p ".$protocol." --dport ".$port." -s ".$host." -j ACCEPT\n";
                # IPv4
                } elsif ($host =~ m/(\d+\.){3}\d+(\/\d+)?$/) {
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
    my $sets_raw = `$ipset list`;
    my $set = '';
    my $members = 0;
    foreach (split(/\n/, $sets_raw)) {
        if ($_ =~ m/^Name: (.*)$/) {
            $set = $1;
            $existing->{$set} = {};
            $members = 0;
            next;
        }
        if (!$members) {
            if ($_ =~ m/Members:/) {
                $members = 1 if ($set =~ /BLACKLIST(IP|NET)/);
            }
            next;
        }
        next if ($_ =~ /^\s*$/);
        $existing->{$set}->{$_} = 1;
    }

    my @blacklist_files = ('/usr/spamtagger/etc/firewall/blacklist.txt', '/usr/spamtagger/etc/firewall/blacklist_custom.txt');
    my $blacklist_script = '/usr/spamtagger/etc/firewall/blacklist';
    unlink $blacklist_script;
    my $BLACKLIST;
    confess ("Failed to open $blacklist_script: $!\n") unless ($BLACKLIST = ${open_as($blacklist_script, ">>", 0755)});
    my $blacklist;
    foreach my $blacklist_file (@blacklist_files) {
        my $BLACK_IP;
        if ( -e $blacklist_file ) {
            unless (defined($blacklist)) {
                print $BLACKLIST "#!/bin/sh\n\n";
                print $BLACKLIST "$ipset create BLACKLISTIP hash:ip\n" unless (defined($existing->{'BLACKLISTIP'}));
                print $BLACKLIST "$ipset create BLACKLISTNET hash:net\n" unless (defined($existing->{'BLACKLISTNET'}));
                foreach my $period (qw( bl 1d 1w 1m 1y )) {
                    foreach my $f2b (keys(%fail2ban_sets)) {
                        print $BLACKLIST "${ipset} create ${f2b}-${period} hash:ip\n" unless (defined($existing->{"${f2b}-${period}"}));
                    }
                }
                $blacklist = 1;
            }
            confess ("Failed to open $blacklist_file: $!\n") unless ($BLACK_IP = ${open_as($blacklist_file, "<")});
            foreach my $IP (<$BLACK_IP>) {
                chomp($IP);
                if ($IP =~ m#/\d+$#) {
                    if ($existing->{'BLACKISTNET'}->{$IP}) {
                        delete($existing->{'BLACKLISTNET'}->{$IP});
                    } else {
                        print $BLACKLIST "${ipset} add BLACKLISTNET $IP\n";
                    }
                } else {
                    if ($existing->{'BLACKISTIP'}->{$IP}) {
                        delete($existing->{'BLACKLISTIP'}->{$IP});
                    } else {
                        print $BLACKLIST "${ipset} add BLACKLISTIP $IP\n";
                    }
                }
            }
            close $BLACK_IP;
        }
    }
    my $remove = '';
    foreach my $list (keys(%{$existing})) {
        foreach my $IP (keys(%{$existing->{$list}})) {
            $remove .= "${ipset} del ${list} ${IP}\n";
        }
    }
    if ($remove ne '') {
        print $BLACKLIST "\n# Cleaning up removed IPs:\n$remove\n";
    }
    if (defined($blacklist)) {
        foreach my $period (qw( bl 1d 1w 1m 1y )) {
            foreach my $f2b (keys(%fail2ban_sets)) {
                my $ports = $services{$fail2ban_sets{$f2b}}[0];
                $ports =~ s/[:|]/,/;
                print $BLACKLIST "${iptables} -I INPUT -p ".lc($services{$fail2ban_sets{$f2b}}[1])." ".($ports =~ m/,/ ? '-m multiport --dports' : '--dport')." ${ports} -m set --match-set ${f2b}-${period} src -j REJECT\n";
                print $BLACKLIST "${iptables} -I INPUT -p ".lc($services{$fail2ban_sets{$f2b}}[1])." ".($ports =~ m/,/ ? '-m multiport --dports' : '--dport')." ${ports} -m set --match-set ${f2b}-${period} src -j LOG\n";
            }
        }
        foreach (qw( BLACKLISTIP BLACKLISTNET )) {
            print $BLACKLIST "${iptables} -I INPUT -m set --match-set $_ st src -j REJECT\n";
            print $BLACKLIST "${iptables} -I INPUT -m set --match-set $_ st src -j LOG\n\n";
        }
        print $START "\n$blacklist_script\n";
    }

    close $BLACKLIST;
    close $START;
}

sub do_stop_script($rules)
{
    my %rules = %{$rules};
    my $stop_script = "${SRCDIR}/etc/firewall/stop";
    unlink($stop_script);

    my $STOP;
    confess "Cannot open $stop_script" unless ( $STOP = ${open_as($stop_script, '>', 0755)} );

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
}

sub getSubnets()
{
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

sub expand_host_string($string, %args)
{
    return $dns->dumper($string,%args);
}
