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
#   This script will dump the ssh key files
#
#   Usage:
#           dump_ssh_keys.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use DBI;
use ReadConfig;

our $config = ReadConfig::get_instance();
my $VARDIR = $config->get_option('VARDIR');

my $DEBUG = 1;

my $known_hosts_file = "$VARDIR/.ssh/known_hosts";
my $authorized_file = "$VARDIR/.ssh/authorized_keys";

unlink($known_hosts_file);
unlink($authorized_file);

do_known_hosts();
my $uid = getpwnam('spamtagger');
my $gid = getgrnam('spamtagger');
chown($uid, $gid, $known_hosts_file);

do_authorized_keys();
chown($uid, $gid, $authorized_file);

############################
sub do_known_hosts {
  my $dbh = DBI->connect(
    "DBI:mariadb:database=st_config;host=localhost;mariadb_socket=$VARDIR/run/mariadb_master/mariadbd.sock",
    "spamtagger", $config->('MYSPAMTAGGERPWD'), {RaiseError => 0, PrintError => 0}
  ) or return;

  my $sth = $dbh->prepare("SELECT hostname, ssh_pub_key FROM slave");
  $sth->execute() or return;

  my $KNOWNHOST;
  open($KNOWNHOST, ">>", $known_hosts_file);
  while (my $ref = $sth->fetchrow_hashref() ) {
    print $KNOWNHOST $ref->{'hostname'}." ".$ref->{'ssh_pub_key'}."\n";
    close $KNOWNHOST;
  }
  $sth->finish();
  return;
}

sub do_authorized_keys {
  my $dbh = DBI->connect(
    "DBI:mariadb:database=st_config;host=localhost;mariadb_socket=$VARDIR/run/mariadb_slave/mariadbd.sock",
    "spamtagger", $config->get_option('MYSPAMTAGGERPWD'), {RaiseError => 0, PrintError => 0}
  ) or return;

  my $sth = $dbh->prepare("SELECT ssh_pub_key FROM master");
  $sth->execute() or return;

  my $AUTHORIZED_KEYS;
  open($AUTHORIZED_KEYS, ">>", $authorized_file);
  while (my $ref = $sth->fetchrow_hashref() ) {
    print $AUTHORIZED_KEYS $ref->{'ssh_pub_key'}."\n";
    close $AUTHORIZED_KEYS;
  }
  $sth->finish();
  return;
}
