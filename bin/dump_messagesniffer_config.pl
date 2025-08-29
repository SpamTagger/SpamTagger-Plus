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
#   This script will dump the messagesniffer configuration file with the configuration
#   settings found in the database.
#
#   Usage:
#           dump_messagesniffer_config.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use DBI;
use ReadConfig;

our $conf = ReadConfig::get_instance();
our $VARDIR = $conf->get_option('VARDIR');
our $SRCDIR = $conf->get_option('SRCDIR');

my $DEBUG = 1;

my $lasterror;

our $dbh = DBI->connect("DBI:mysql:database=st_config;host=localhost;mysql_socket=$VARDIR/run/mysql_slave/mysqld.sock",
  "spamtagger", $conf->get_option('MYSPAMTAGGERPWD'), {RaiseError => 0, PrintError => 0}
) or fatal_error("CANNOTCONNECTDB", $dbh->errstr);

my %messagesniffer_conf;
%messagesniffer_conf = get_messagesniffer_config() or fatal_error("NOMESSAGESNIFFERCONFIGURATIONFOUND", "no MessageSniffer configuration found");

$dbh->db_disconnect();

if (!defined($messagesniffer_conf{'__LICENSEID__'})) {
  $messagesniffer_conf{'__LICENSEID__'} = '';
}
if (!defined($messagesniffer_conf{'__AUTHENTICATION__'})) {
  $messagesniffer_conf{'__AUTHENTICATION__'} = '';
}

my $uid = getpwnam( 'snfuser' );
my $gid = getgrnam( 'snfuser' );

dump_file("SNFServer.xml");
chown $uid, $gid, "SNFServer.xml";
dump_file("identity.xml");
chown $uid, $gid, "identity.xml";
dump_file("getRulebase");
chown $uid, $gid, "getRulebase";

chmod o755, "$SRCDIR'}/etc/messagesniffer/getRulebase";

print "DUMPSUCCESSFUL";

#############################
sub dump_file ($file) {
  my $template_file = "$SRCDIR'}/etc/messagesniffer/".$file."_template";
  my $target_file = "$SRCDIR'}/etc/messagesniffer/".$file;

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

  my $proxy_server = "";
  my $proxy_port = "";
  if ($conf->get_option('HTTPPROXY')) {
    if ($conf->get_option('HTTPPROXY') =~ m/http\:\/\/(\S+)\:(\d+)/) {
      $proxy_server = $1;
      $proxy_port = $2;
    }
  }

  while(my $line = <$TEMPLATE>) {
    $line =~ s/__VARDIR__/$VARDIR/g;
    $line =~ s/__SRCDIR__/$SRCDIR/g;
    if ($proxy_server =~ m/\S+/) {
      $line =~ s/\#HTTPProxyServer __HTTPPROXY__/HTTPProxyServer $proxy_server/g;
      $line =~ s/\#HTTPProxyPort __HTTPPROXYPORT__/HTTPProxyPort $proxy_port/g;
    }
    $line =~ s/__LICENSEID__/$messagesniffer_conf{'__LICENSEID__'}/g;
    $line =~ s/__AUTHENTICATION__/$messagesniffer_conf{'__AUTHENTICATION__'}/g;

    print $TARGET $line;
  }

  close $TEMPLATE;
  close $TARGET;

  return 1;
}

#############################
sub get_messagesniffer_config {
  my %config;

  my $sth = $dbh->prepare("SELECT licenseid, authentication FROM MessageSniffer");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  return if ($sth->rows < 1);

  $config{'__LICENSEID__'} = $ref->{'licenseid'};
  $config{'__AUTHENTICATION__'} = $ref->{'authentication'};

  $sth->finish();
  return %config;
}
