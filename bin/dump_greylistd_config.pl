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
#   This script will dump the exim configuration file from the configuration
#   setting found in the database.
#
#   Usage:
#           dump_greylistd_config.pl
#

use v5.40;
use strict;
use warnings;
use utf8;
use Carp qw( confess );

my ($SRCDIR, $VARDIR);
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
use File::Touch;
use File::Path qw(make_path);

require DB;

my $DEBUG = 0;

my %greylist_conf = get_greylist_config();
my $trusted_ips = get_trusted_ips();

our $uid = getpwnam( 'greylist' );
our $gid = getgrnam( 'greylist' );
our $confdir = "/etc/greylistd";

foreach my $dir (
    "${VARDIR}/spool/greylistd",
    "${VARDIR}/run/greylistd"
) {
    chmod(0755, $dir) if ( -d $dir );
    make_path($dir, {'mode'=>0755,'user'=>$uid,'group'=>$gid}) unless ( -d $dir );
}

if ( -e $confdir && !-l $confdir ) {
    unlink(glob($confdir."/*"));
    rmdir($confdir);
}

symlink("${SRCDIR}/${confdir}", $confdir);

symlink($SRCDIR.'/etc/apparmor', '/etc/apparmor.d/spamtagger') unless (-e '/etc/apparmor.d/spamtagger');

dump_greylistd_file(\%greylist_conf);

dump_domain_to_avoid($greylist_conf{'__AVOID_DOMAINS__'});

dump_trusted_ips($trusted_ips);

foreach my $dir (
    "/etc/greylistd",
    glob("/etc/greylistd/*"),
    "${VARDIR}/spool/greylistd",
) {
    mkdir($dir) unless (-d $dir);
    chown($uid, $gid, $dir);
}

foreach my $file (
    glob("${VARDIR}/spool/greylistd/*"),
    "${VARDIR}/spool/tmp/spamtagger/domains_to_greylist.list",
    "${SRCDIR}/${confdir}/config",
    "${SRCDIR}/${confdir}/whitelist-hosts",
) {
    touch($file) unless(-f $file);
    chown($uid, $gid, $file);
}

sub get_greylist_config()
{
    my $replica_db = DB->db_connect('replica', 'st_config');

    my %configs = $replica_db->get_hash_row(
        "SELECT retry_min, retry_max, expire, avoid_domains FROM greylistd_config"
    );
    my %ret;

    $ret{'__RETRYMIN__'} = $configs{'retry_min'};
    $ret{'__RETRYMAX__'} = $configs{'retry_max'};
    $ret{'__EXPIRE__'} = $configs{'expire'};
    $ret{'__AVOID_DOMAINS__'} = $configs{'avoid_domains'};

    return %ret;
}

sub get_trusted_ips()
{
    my $replica_db = DB->db_connect('replica', 'st_config');

    my %configs = $replica_db->get_hash_row(
        "SELECT trusted_ips FROM antispam;"
    );

    return $configs{'trusted_ips'};
}

sub dump_domain_to_avoid($domains)
{
    my @domains_to_avoid;
    if (! $domains eq "") {
        @domains_to_avoid = split /\s*[\,\:\;]\s*/, $domains;
    }

    my $dir = "${VARDIR}/spool/tmp/spamtagger/";
    make_path($dir, {'mode'=>0755,'user'=>$uid,'group'=>$gid}) unless ( -d $dir );
    my $file = "${dir}/domains_to_avoid_greylist.list";
    my $DOMAINTOAVOID;
    confess "Cannot open $file: $!" unless ($DOMAINTOAVOID = ${open_as($file)} );

    foreach my $adomain (@domains_to_avoid) {
        print $DOMAINTOAVOID $adomain."\n";
    }
    close $DOMAINTOAVOID;
}

sub dump_trusted_ips($ips)
{
    my $file = "${SRCDIR}/${confdir}/whitelist-hosts";
    unlink($file) if (-e $file);
    return 0 unless (defined($ips));
    return 0 if ($ips =~ /^\s*$/);
    my $TRUSTED_IPS;
    confess "Cannot open $file: $!" unless ($TRUSTED_IPS = ${open_as($file)} );
    print $TRUSTED_IPS $ips;
    close $TRUSTED_IPS;
}

sub dump_greylistd_file($greylistd_conf)
{
    my $template_file = "${SRCDIR}/${confdir}/greylistd.conf_template";
    my $target_file = "${SRCDIR}/${confdir}/config";

    my ($TEMPLATE, $TARGET);
    confess "Cannot open $template_file: $!\n" unless ($TEMPLATE = ${open_as($template_file, '<')} );
    confess "Cannot open $target_file: $!\n" unless ($TARGET = ${open_as($target_file)} );

    while(<$TEMPLATE>) {
        my $line = $_;

        $line =~ s/__VARDIR__/$VARDIR/g;
        $line =~ s/__SRCDIR__/$SRCDIR/g;

        foreach my $key (keys %{$greylistd_conf}) {
            $line =~ s/$key/$greylistd_conf->{$key}/g;
        }

        print $TARGET $line;
    }

    close $TEMPLATE;
    close $TARGET;
}
