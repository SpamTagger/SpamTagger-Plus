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
#   This script will dump the whitelist and warnlists for the system/domain/user
#
#   Usage:
#           dump_wwlists.pl [domain|user]

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
    $SRCDIR = $conf->get_option('SRCDIR');
    $VARDIR = $conf->get_option('VARDIR');
    unshift(@INC, $SRCDIR."/lib");
}

use STUtils qw( open_as );
use File::Path qw( make_path );

require DB;

my $uid = getpwnam( 'spamtagger' );
my $gid = getgrnam( 'spamtagger' );

my $what = shift;
if (!defined($what)) {
    $what = "";
}
my $to = "";
my $filepath = "${VARDIR}/spool/spamtagger/prefs/";
if ($what =~ /^\@([a-zA-Z0-9\.\_\-]+)$/) {
    $to = $what;
    $filepath .= $1."/_global/";
} elsif ($what =~ /^([a-zA-Z0-9\.\_\-]+)\@([a-zA-Z0-9\.\_\-]+)/) {
    $to = $what;
    $filepath .= $2."/".$1."@".$2."/";
} else {
    $filepath .= "_global/";
}

my $replica_db = DB->db_connect('replica', 'st_config');

dump_ww_files($to, $filepath);

$replica_db->disconnect();

sub dump_ww_files($to,$filepath)
{
    my @types = ('warn', 'white');

    foreach my $type (@types) {
        my @list = $replica_db->get_list("SELECT sender FROM wwlists WHERE
            status=1 AND type='".$type."' AND recipient='".$to."'"
        );

        my $file = $filepath."/".$type.".list";
        if ( -f $file) {
            unlink $file;
        }

        next unless (scalar(@list));

        make_path($filepath, {'mode'=>0o755,'user'=>'spamtagger','group'=>'spamtagger'});

        my $WWFILE;
        confess "Failed to open $file\n" unless ($WWFILE = ${open_as($file, '>>')});

        print $WWFILE "$_\n" foreach (@list);

        close $WWFILE;
    }
    return 1;
}
