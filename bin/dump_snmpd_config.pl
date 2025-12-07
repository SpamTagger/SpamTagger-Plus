#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
#   Copyright (C) 2025 John Mertz <git@john.me.tz>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#   This script will dump the snmp configuration file from the configuration
#   setting found in the database.
#
#   Usage:
#           dump_snmp_config.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use File::Path qw(mkpath);
use Term::ReadKey();
use DB();
use ReadConfig();
use GetDNS();

our $dns = GetDNS->new();
our $config = ReadConfig::get_instance();
our $SRCDIR = $config->get_option('SRCDIR');
our $VARDIR = $config->get_option('VARDIR');

my $DEBUG = 1;

my $system_mibs_file = '/usr/share/snmp/mibs/SPAMTAGGER-MIB.txt';
mkpath('/usr/share/snmp/mibs') if ( ! -d '/usr/share/snmp/mibs');

my $st_mib_file = "$SRCDIR/www/guis/admin/public/downloads/SPAMTAGGER-MIB.txt";

my $lasterror = "";

my $dbh;
$dbh = DB->db_connect('replica', 'st_config') or fatal_error("CANNOTCONNECTDB", $dbh->errstr);

my %snmpd_conf;
%snmpd_conf = get_snmpd_config() or fatal_error("NOSNMPDCONFIGURATIONFOUND", "no snmpd configuration found");

my %source_hosts;
%source_hosts = get_source_config();

dump_snmpd_file() or fatal_error("CANNOTDUMPSNMPDFILE", $lasterror);

$dbh->db_disconnect();

unlink($system_mibs_file) if (-f $system_mibs_file);

symlink($st_mib_file,$system_mibs_file);
print "DUMPSUCCESSFUL";

#############################
sub dump_snmpd_file ($stage) {
  my $template_file = "$SRCDIR/etc/snmp/snmpd.conf_template";
  my $target_file = "$SRCDIR/etc/snmp/snmpd.conf";

  my $ipv6 = 0;
  my $interfaces;
  if (open($interfaces, '<', '/etc/network/interfaces')) {
    while (<$interfaces>) {
      if ($_ =~ m/iface \S+ inet6/) {
        $ipv6 = 1;
        last;
      }
    }
    close($interfaces);
  }

  my ($TEMPLATE, $TARGET);
  unless (open($TEMPLATE, '<', $template_file) ) {
    $lasterror = "Cannot open template file: $template_file";
    return 0;
  }
  unless (open($TARGET, ">", $target_file) ) {
    $lasterror = "Cannot open target file: $target_file";
    close $template_file;
    return 0;
  }

  my @ips = expand_host_string($snmpd_conf{'__ALLOWEDIP__'}.' 127.0.0.1',{'dumper'=>'snmp/allowedip'});
  my $ip;
  foreach my $ip ( keys %source_hosts) {
    print $TARGET "com2sec local     $ip     $snmpd_conf{'__COMMUNITY__'}\n";
    print $TARGET "com2sec6 local     $ip     $snmpd_conf{'__COMMUNITY__'}\n";
  }
  foreach my $ip (@ips) {
    print $TARGET "com2sec local     $ip  $snmpd_conf{'__COMMUNITY__'}\n";
    if ($ipv6) {
      print $TARGET "com2sec6 local     $ip     $snmpd_conf{'__COMMUNITY__'}\n";
    }
  }

  while(my $line = <$TEMPLATE>) {
    $line =~ s/__VARDIR__/$VARDIR/g;
    $line =~ s/__SRCDIR__/$SRCDIR/g;

    print $TARGET $line;
  }

  my @disks = split(/\:/, $snmpd_conf{'__DISKS__'});
  my $disk;
  foreach my $disk (@disks) {
    print $TARGET "disk      $disk   100000\n";
  }

  close $TEMPLATE;
  close $TARGET;

  return 1;
}

#############################
sub get_snmpd_config{
  my %config;

  my $sth = $dbh->prepare("SELECT allowed_ip, community, disks FROM snmpd_config");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  return if ($sth->rows < 1);
  my $ref = $sth->fetchrow_hashref() or return;

  $config{'__ALLOWEDIP__'} = join(' ',expand_host_string($ref->{'allowed_ip'},{'dumper'=>'snmp/allowedip'}));
  $config{'__COMMUNITY__'} = $ref->{'community'};
  $config{'__DISKS__'} = $ref->{'disks'};

  $sth->finish();
  return %config;
}

#############################
sub get_source_config {
  my %sources;

  my $sth = $dbh->prepare("SELECT hostname FROM source");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  return if ($sth->rows < 1);
  while (my $ref = $sth->fetchrow_hashref()) {
    $sources{$ref->{'hostname'}} = 1;
  }

  $sth->finish();
  return %sources;
}

#############################
sub fatal_error ($msg, $full) {
  print $msg;
  if ($DEBUG) {
    print "\n Full information: $full \n";
  }
  exit(0);
}

#############################
sub print_usage {
  print "Bad usage: dump_exim_config.pl [stage-id]\n\twhere stage-id is an integer between 0 and 4 (0 or null for all).\n";
  exit(0);
}

sub expand_host_string ($string, $args = {}) {
  return $dns->dumper($string,$args);
}
