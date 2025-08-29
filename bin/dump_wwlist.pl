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
#   This script will dump the whitelist and warnlists for the system/domain/user
#
#   Usage:
#           dump_wwlists.pl [domain|user]

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use ReadConfig();
use DB();

my $conf = ReadConfig::get_instance();
my $op = $conf->get_option('SRCDIR');
my $uid = getpwnam( 'spamtagger' );
my $gid = getgrnam( 'spamtagger' );

my $what = shift;
if (!defined($what)) {
  $what = "";
}
my $to = "";
my $filepath = $conf->get_option('VARDIR')."/spool/spamtagger/prefs/";
if ($what =~ /^\@([a-zA-Z0-9\.\_\-]+)$/) {
  $to = $what;
  $filepath .= $1."/_global/";
} elsif ($what =~ /^([a-zA-Z0-9\.\_\-]+)\@([a-zA-Z0-9\.\_\-]+)/) {
  $to = $what;
  $filepath .= $2."/".$1."@".$2."/";
} else {
  $filepath .= "_global/";
}

dump_ww_files($to, $filepath);
print "DUMPSUCCESSFUL";
exit 0;

#####################################
## dump_wwfiles

sub dump_ww_files ($to, $filepath) {
  my @types = ('warn', 'white');

  my $slave_db = DB->db_connect('slave', 'st_config');

  foreach my $type (@types) {
    ## get list
    my @list = $slave_db->get_list(
      "SELECT sender FROM wwlists WHERE status=1 AND type='".$type."' AND recipient='".$to."'"
    );

    # first remove file if exists
    my $file = $filepath."/".$type.".list";
    if ( -f $file) {
       unlink $file;
    }

    # exit if list empty
    if (!@list) {
       next;
    }

    # create directory if needed
    create_dirs($filepath);

    # and write the file down
    my $WWFILE;
    return 0 unless (open($WWFILE, ">", $file) );

    print $WWFILE "$_\n" foreach (@list);

    close $WWFILE;
    chown 'spamtagger', $file;
  }
  $slave_db->db_disconnect();
  return 1;
}

#####################################
## create_dir

sub create_dirs($path) {
  my $cmd = "mkdir -p $path";
  my $res = `$cmd`;
  chown $uid, $gid, $path;
  return;
}
