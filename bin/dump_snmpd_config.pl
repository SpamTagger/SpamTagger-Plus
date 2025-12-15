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
#
#   This script will dump the snmp configuration file from the configuration
#   setting found in the database.
#
#   Usage:
#           dump_snmp_config.pl

use v5.40;
use strict;
use warnings;
use utf8;
use Carp qw( confess );

our ($SRCDIR, $VARDIR);
BEGIN {
    if ($0 =~ m/(\S*)\/\S+.pl$/) {
        my $path = $1."/../lib";
        unshift (@INC, $path);
    }
    require ReadConfig;
    my $conf = ReadConfig::get_instance();
    $SRCDIR = $conf->get_option('SRCDIR') || '/usr/spamtagger';
    $VARDIR = $conf->get_option('VARDIR') || '/var/spamtagger';
}

use STUtils qw(open_as);
use File::Path qw(mkpath);
require DB;
require GetDNS;

our $DEBUG = 1;
our $uid = getpwnam('Debian-snmp');
our $gid = getpwnam('spamtagger');

my $system_mibs_file = '/usr/share/snmp/mibs/SPAMTAGGER-MIB.txt';
if ( ! -d '/usr/share/snmp/mibs') {
    mkpath('/usr/share/snmp/mibs');
}
my $st_mib_file = "${SRCDIR}/www/guis/admin/public/downloads/SPAMTAGGER-MIB.txt";

my $lasterror = "";

our $dbh = DB->db_connect('replica', 'st_config');

my %snmpd_conf;
confess "Error fetching snmp config: $!" unless %snmpd_conf = get_snmpd_config();

my @source_hosts = get_source_config();

confess "Error dumping snmp config: $!" unless dump_snmpd_file();

if ( !-d "/var/spamtagger/log/snmpd/") {
    mkdir("/var/spamtagger/log/snmpd/") || confess("Failed to create '/var/spamtagger/log/snmpd/'\n");
    chown($uid, $gid, "/var/spamtagger/log/snmpd/");
}
if ( !-d "/var/spamtagger/run/snmpd/") {
    mkdir("/var/spamtagger/run/snmpd/") || confess("Failed to create '/var/spamtagger/run/snmpd/'\n");
    chown($uid, $gid, "/var/spamtagger/run/snmpd/");
}
if (-f $system_mibs_file) {
    unlink($system_mibs_file);
}
symlink($st_mib_file,$system_mibs_file);
chown($uid, $gid, $system_mibs_file);

symlink($SRCDIR.'/etc/apparmor', '/etc/apparmor.d/spamtagger') unless (-e '/etc/apparmor.d/spamtagger');

sub setup_snmpd_dir() {
    my $include = 0;
    my $main = '/etc/snmp/snmpd.conf';
    chown($uid, $gid, "/etc/snmp", $main);
    if ( -e $main) {
        if (open(my $fh, '<', $main)) {
            while (<$fh>) {
                if ($_ =~ m#includeDir ${main}.d#) {
                    $include = 1;
                }
                last;
            }
            close($fh);
        }
    }
    unless ($include) {
        if (open(my $fh, '>>', $main)) {
            print $fh "includeDir ${main}.d";
            close($fh);
            $include = 1;
        } else {
            confess("Failed to open '/etc/snmp/snmpd.conf' for writing");
        }
    }
    if ( !-d "${main}.d") {
        mkdir("${main}.d") || confess("Failed to create '${main}.d'\n");
    }
    chown($uid, $gid, $main, "${main}.d");
    return 1;
}

sub dump_snmpd_file()
{
    setup_snmpd_dir() || confess("Failed to create/verify '/etc/snmp/snmpd.conf.d'\n");

    my $template_file = "${SRCDIR}/etc/snmp/snmpd.conf_template";
    my $target_file = "/etc/snmp/snmpd.conf.d/spamtagger.conf";
    unlink($target_file);

    my $ipv6 = 0;
    if (open(my $interfaces, '<', '/etc/network/interfaces')) {
        while (<$interfaces>) {
            if ($_ =~ m/iface \S+ inet6/) {
                $ipv6 = 1;
                last;
            }
        }
        close($interfaces);
    }

    my ($TEMPLATE, $TARGET);
    confess "Cannot open $template_file: $!" unless ($TEMPLATE = ${open_as($template_file, '<')} );
    confess "Cannot open $target_file: $!" unless ($TARGET = ${open_as($target_file)} );

    print $TARGET "agentAddress /var/spamtagger/run/snmpd/snmpd.sock\n";
    my @ips = expand_host_string($snmpd_conf{'__ALLOWEDIP__'}.' 127.0.0.1',{'dumper'=>'snmp/allowedip'});
    foreach my $ip (@source_hosts) {
        print $TARGET "com2sec local     $ip     $snmpd_conf{'__COMMUNITY__'}\n";
        print $TARGET "com2sec6 local     $ip     $snmpd_conf{'__COMMUNITY__'}\n";
    }
    foreach my $ip (@ips) {
        print $TARGET "com2sec local     $ip    $snmpd_conf{'__COMMUNITY__'}\n";
        if ($ipv6) {
            print $TARGET "com2sec6 local     $ip     $snmpd_conf{'__COMMUNITY__'}\n";
        }
    }

    while(<$TEMPLATE>) {
        my $line = $_;

        $line =~ s/__VARDIR__/${VARDIR}/g;
        $line =~ s/__SRCDIR__/${SRCDIR}/g;

        print $TARGET $line;
    }

    my @disks = split(/\:/, $snmpd_conf{'__DISKS__'});
    foreach my $disk (@disks) {
        print $TARGET "disk      $disk   100000\n";
    }

    close $TEMPLATE;
    close $TARGET;

    chown($uid, $gid, $target_file);
    return 1;
}

#############################
sub get_snmpd_config
{
    my %config;

    my @snmp = $dbh->get_list_of_hash("SELECT allowed_ip, community, disks FROM snmpd_config");

    $config{'__ALLOWEDIP__'} = join(' ',expand_host_string($snmp[0]->{'allowed_ip'},{'dumper'=>'snmp/allowedip'}));
    $config{'__COMMUNITY__'} = $snmp[0]->{'community'};
    $config{'__DISKS__'} = $snmp[0]->{'disks'};

    return %config;
}

#############################
sub get_source_config
{
    my %sources;
    my @hostnames = $dbh->get_list("SELECT hostname FROM source");

    return @hostnames;
    $sources{$_->{'hostname'}} = 1 foreach (@hostnames);

    return keys(%sources);
}

sub expand_host_string($string, $args)
{
    my $dns = GetDNS->new();
    return $dns->dumper($string,$args);
}
