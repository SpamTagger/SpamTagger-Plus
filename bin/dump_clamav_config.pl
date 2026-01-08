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
#   This script will dump the clamav configuration file with the configuration
#   settings found in the database.
#
#   Usage:
#           dump_clamav_config.pl

use v5.40;
use strict;
use warnings;
use utf8;
use Carp qw( confess );

our ($SRCDIR, $VARDIR, $HTTPPROXY);
BEGIN {
    if ($0 =~ m/(\S*)\/\S+.pl$/) {
        my $path = $1."/../lib";
        unshift (@INC, $path);
    }
    require ReadConfig;
    my $conf = ReadConfig::get_instance();
    $SRCDIR = $conf->get_option('SRCDIR');
    $VARDIR = $conf->get_option('VARDIR');
    $HTTPPROXY = $conf->get_option('HTTPPROXY');
    unshift(@INC, $SRCDIR."/lib");
}

use STUtils qw( open_as rmrf );

my $lasterror;

my $uid = getpwnam( 'clamav' );
my $gid = getgrnam( 'spamtagger' );
my $conf = '/etc/clamav';

if (-e $conf && ! -s $conf) {
	unlink(glob("$conf/*"), $conf);
}
symlink($SRCDIR."/".$conf, $conf) unless (-l $conf);
unless (-l "/var/lib/clamav/") {
	rmrf("/var/lib/clamav/") if (-e "/var/lib/clamav");
	printf("Creating symlink $VARDIR/spool/clamav\n");
	symlink($VARDIR."/spool/clamav", "/var/lib/clamav");
}

# Create necessary dirs/files if they don't exist
foreach my $dir (
    "/etc/clamav",
    $SRCDIR."/etc/clamav",
    $VARDIR."/log/clamav",
    $VARDIR."/run/clamav",
    $VARDIR."/spool/clamav",
) {
    mkdir($dir) unless (-d $dir);
    chown($uid, $gid, $dir);
}

foreach my $file (
    glob($SRCDIR."/etc/clamav/*"),
    glob($VARDIR."/log/clamav/*"),
    glob($VARDIR."/run/clamav/*"),
    glob($VARDIR."/spool/clamav/*"),
) {
    print("Taking ownership of $file\n");
    chown($uid, $gid, $file);
}

# Configure sudoer permissions if they are not already
mkdir '/etc/sudoers.d' unless (-d '/etc/sudoers.d');
if (open(my $fh, '>', '/etc/sudoers.d/clamav')) {
    print $fh "
User_Alias  CLAMAV = clamav
Cmnd_Alias  CLAMBIN = /usr/sbin/clamd

CLAMAV      * = (ROOT) NOPASSWD: CLAMBIN
";
}

symlink($SRCDIR.'/etc/apparmor', '/etc/apparmor.d/clamav') unless (-e '/etc/apparmor.d/clamav');

# Reload AppArmor rules
`apparmor_parser -r ${SRCDIR}/etc/apparmor.d/clamav` if ( -d '/sys/kernel/security/apparmor' );

# SystemD auth causes timeouts
`sed -iP '/^session.*pam_systemd.so/d' /etc/pam.d/common-session`;

# Dump configuration
dump_file("clamav.conf");
dump_file("clamd.conf");
dump_file("freshclam.conf");

#############################
sub dump_file($file)
{
    my $template_file = $SRCDIR."/etc/clamav/".$file."_template";
    my $target_file = $SRCDIR."/etc/clamav/".$file;

    my ($TEMPLATE, $TARGET);
    confess "Cannot open $template_file" unless ( $TEMPLATE = ${open_as($template_file,'<',0o664,'clamav:clamav')} );
    confess "Cannot open $template_file" unless ( $TARGET = ${open_as($target_file,'>',0o664,'clamav:clamav')} );

    my $proxy_server = "";
    my $proxy_port = "";
    if ($HTTPPROXY) {
        if ($HTTPPROXY =~ m/http\:\/\/(\S+)\:(\d+)/) {
            $proxy_server = $1;
            $proxy_port = $2;
        }
    }

    while(<$TEMPLATE>) {
        my $line = $_;

        $line =~ s/__VARDIR__/${VARDIR}/g;
        $line =~ s/__SRCDIR__/${SRCDIR}/g;
        if ($proxy_server =~ m/\S+/) {
            $line =~ s/\#HTTPProxyServer __HTTPPROXY__/HTTPProxyServer $proxy_server/g;
            $line =~ s/\#HTTPProxyPort __HTTPPROXYPORT__/HTTPProxyPort $proxy_port/g;
        }

        print $TARGET $line;
    }

    if (($file eq "clamd.conf") && ( -e "/var/spamtagger/spool/spamtagger/mc-experimental-macros")) {
        print $TARGET "OLE2BlockMacros yes";
    }

    close $TEMPLATE;
    close $TARGET;

    return 1;
}
