#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
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
#   This script will dump the mysql configuration file from the configuration
#   setting found in the database.
#
#   Usage:
#           dump_mysql_config.pl

use v5.40;
use warnings;
use utf8;

my $DEBUG = 1;

use lib '/usr/spamtagger/lib/';
use ReadConfig;

our $conf = ReadConfig::get_instance();
our $SRCDIR = $conf->get_option('SRCDIR');
our $VARDIR = $conf->get_option('VARDIR');
my %config = ();

## added 10 for migration ease
$config{'__MASTERID__'} = ($conf->get_option('HOSTID') * 2) - 1 + 10;
$config{'__SLAVEID__'} = $conf->get_option('HOSTID') * 2 + 10;

## Avoid having unsychronized database when starting a new VA
my $FIRSTUPDATE_FLAG_RAN="$VARDIR/run/configurator/updater4st-ran";
if (-e $FIRSTUPDATE_FLAG_RAN){
  $config{'__BINARY_LOG_KEEP__'} = 21;
} else {
  $config{'__BINARY_LOG_KEEP__'} = 0;
}

my $lasterror = "";

dump_mysql_file('master') or fatal_error("CANNOTDUMPMYSQLFILE", $lasterror);
dump_mysql_file('slave') or fatal_error("CANNOTDUMPMYSQLFILE", $lasterror);

print "DUMPSUCCESSFUL";

#############################
sub dump_mysql_file ($stage) {
  my $template_file = "$SRCDIR/etc/mysql/my_$stage.cnf_template";
  my $target_file = "$SRCDIR/etc/mysql/my_$stage.cnf";

  unless (open($TEMPLATE, "<", $template_file) ) {
    $lasterror = "Cannot open template file: $template_file";
    return 0;
  }
  unless (open($TARGET, ">", "$target_file") ) {
    $lasterror = "Cannot open target file: $target_file";
    close $template_file;
    return 0;
  }

  while($line = <$TEMPLATE>) {
    $line =~ s/__VARDIR__/$VARDIR/g;
    $line =~ s/__SRCDIR__/$SRCDIR/g;

    $line =~ s/$_/$config{$_}/g foreach (keys(%config);

    print $TARGET $line;
  }

  close $TEMPLATE;
  close $TARGET;

  return 1;
}

#############################
sub fatal_error ($msg, $full) {
  print $msg;
  print "\n Full information: $full \n" if ($DEBUG);
  exit(0);
}

#############################
sub print_usage {
  print "Bad usage: dump_mysql_config.pl\n";
  exit(0);
}
