#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2020 MailCleaner
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
#   This script will dump the ssh key files
#
#   Usage:
#     dump_html_controls_wl.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use DBI;
use ReadConfig;

our $config = ReadConfig::get_instance();

my $file = '/var/spamtagger/spool/tmp/mailscanner/whitelist_HTML';
unlink($file);

do_htmls_wl();

############################
sub do_htmls_wl {
  my $dbh;
  $dbh = DBI->connect("DBI:mariadb:database=st_config;host=localhost;mariadb_socket=".$config->get_option('VARDIR')."/run/mariadb_slave/mariadbd.sock",
      "spamtagger", $config->get_option('MYSPAMTAGGERPWD'), {RaiseError => 0, PrintError => 0})
      or return;

  my $sth = $dbh->prepare("SELECT sender FROM wwlists WHERE type='htmlcontrols'");
  $sth->execute() or return;

  my $count=0;

  my $HTML_WL;
  open($HTML_WL, '>', $file);
  while (my $ref = $sth->fetchrow_hashref() ) {
    print $HTML_WL $ref->{'sender'}."\n";
    $count++;
  }
  $sth->finish();
  close $HTML_WL;

  # Unlink file if it is empty
  unlink $file unless $count;

  return;
}
