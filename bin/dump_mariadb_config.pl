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
#   This script will dump the mariadb configuration file from the configuration
#   setting found in the database.
#
#   Usage:
#           dump_mariadb_config.pl

use v5.40;
use strict;
use warnings;
use utf8;
use Carp qw( confess );

our ($conf, $SRCDIR, $VARDIR, $HOSTID);
BEGIN {
    if ($0 =~ m/(\S*)\/\S+.pl$/) {
        my $path = $1."/../lib";
        unshift (@INC, $path);
    }
    require ReadConfig;
    $conf = ReadConfig::get_instance();
    $SRCDIR = $conf->get_option('SRCDIR') || '/usr/spamtagger';
    $VARDIR = $conf->get_option('VARDIR') || '/var/spamtagger';
    confess "Failed to get HOSTID from '/etc/spamtagger.conf'" unless ($HOSTID = $conf->get_option('HOSTID'));
}

use STUtils qw(open_as);
use File::Path qw(make_path);
require DB;

our $DEBUG = 1;
our $uid = getpwnam( 'spamtagger' );
our $gid = getgrnam( 'spamtagger' );

## added 10 for migration ease
my %config;
$config{'HOSTID'} = ${HOSTID};
$config{'__SOURCEID__'} = (${HOSTID} * 2) - 1 + 10;
$config{'__REPLICAID__'} = ${HOSTID} * 2 + 10;

## Avoid having unsychronized database when starting a new VA
my $FIRSTUPDATE_FLAG_RAN="${VARDIR}/run/configurator/updater4st-ran";
if (-e $FIRSTUPDATE_FLAG_RAN){
    $config{'__BINARY_LOG_KEEP__'} = 21;
} else {
    $config{'__BINARY_LOG_KEEP__'} = 0;
}

my $lasterror = "";

my @stages = ('source', 'replica');
if (scalar(@ARGV)) {
    use List::Util qw (uniq);
    @stages = uniq( map { $_ =~ s/\/nopass//; $_ } @ARGV );
    foreach (@stages) {
        confess "Invalid database $_" unless ($_ =~ /^(replica|source)$/);
    }
}
foreach my $stage (@stages) {
    confess "CANNOTDUMPMYSQLFILE" unless (dump_mariadb_file($stage,%config));
    ownership($stage);
}

#############################
sub dump_mariadb_file($stage,%config)
{
    my $template_file = "${SRCDIR}/etc/mariadb/my_${stage}.cnf_template";
    my $target_file = "${SRCDIR}/etc/mariadb/my_${stage}.cnf";

    my ($TEMPLATE, $TARGET);
    confess "Cannot open $template_file: $!" unless ($TEMPLATE = ${open_as($template_file, '<', 0664, 'spamtagger:spamtagger')});
    confess "Cannot open ${target_file}: $!" unless ($TARGET = ${open_as("${target_file}", '>', 0664, 'spamtagger:spamtagger')});

    while(<$TEMPLATE>) {
        my $line = $_;

        $line =~ s/__VARDIR__/${VARDIR}/g;
        $line =~ s/__SRCDIR__/${SRCDIR}/g;

        foreach my $key (keys %config) {
            $line =~ s/$key/$config{$key}/g;
        }

        print $TARGET $line;
    }

    close $TEMPLATE;
    close $TARGET;

    return 1;
}

sub ownership($stage)
{
    use File::Touch qw( touch );

    unless ( -e "/usr/lib/systemd/system/mariadb\@.service.d" ) {
	symlink("${SRCDIR}/scripts/systemd/mariadb\@.service.d", "/usr/lib/systemd/system/mariadb\@.service.d");
	`systemctl daemon-reload`;
    }
    unless ( -e "/usr/lib/systemd/system/mariadb\@${stage}.service.d" ) {
	symlink("${SRCDIR}/scripts/systemd/mariadb\@${stage}.service.d", "/usr/lib/systemd/system/mariadb\@${stage}.service.d");
	`systemctl daemon-reload`;
    }
    unless ( -e "/usr/lib/systemd/system/mariadb\@${stage}-nopass.service.d" ) {
	symlink("${SRCDIR}/scripts/systemd/mariadb\@${stage}-nopass.service.d", "/usr/lib/systemd/system/mariadb\@${stage}-nopass.service.d");
	`systemctl daemon-reload`;
    }
    symlink($SRCDIR.'/etc/apparmor', '/etc/apparmor.d/spamtagger') unless (-e '/etc/apparmor.d/spamtagger');

    # Reload AppArmor rules
    `apparmor_parser -r ${SRCDIR}/etc/apparmor.d/mariadb` if ( -d '/sys/kernel/security/apparmor' );

    mkdir('/etc/sudoers.d') unless (-d '/etc/sudoers.d/');
    if (open(my $fh, '>', '/etc/sudoers.d/mariadb')) {
        print $fh "
User_Alias  MYSQL = spamtagger
Cmnd_Alias  START = /usr/bin/mariadbd-safe
Cmnd_Alias  INSTALL = /usr/bin/mariadb-install_db
Cmnd_Alias  UPGRADE = /usr/bin/mariadb-upgrade

M%SQL       * = (ROOT) NOPASSWD: START
M%SQL       * = (ROOT) NOPASSWD: INSTALL
M%SQL       * = (ROOT) NOPASSWD: UPGRADE
";
    }
    my @dirs = (
        "${VARDIR}/run/mariadb_${stage}",
        "${VARDIR}/log/mariadb_${stage}",
        "${VARDIR}/spool/mariadb_${stage}",
        "${VARDIR}/spool/mariadb_${stage}",
    );
    foreach my $dir (@dirs) {
	my ($path) = $dir =~ m#(.*)/[^/]+$#;

	print "Creating dir: $dir\n";
	mkdir ($dir) unless (-d $dir);
	chown($uid, $gid, $dir);
        symlink("${dir}","${path}/mysql_${stage}") if ( ! -e "${path}/mysql_${stage}");
    }

    my @files = (
	glob("${VARDIR}/log/mariadb_${stage}/*"),
	glob("${VARDIR}/spool/mariadb_${stage}/*"),
    );
    foreach (glob("${VARDIR}/spool/mariadb_${stage}/*")) {
        push(@files, glob("$_/*"));
    }
    foreach my $file (@files) {
	touch($file) unless (-e $file);
        chown($uid, $gid, $file);
        chmod 0744, $file;
    }
}
