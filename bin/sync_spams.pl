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
#
#   This script will force a spam message stored on the quarantine
#
#   Usage:
#           sync_spams.pl [-D]
#             -D: output debug information
#   synchronize slave spam quarantine database with master

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use Net::SMTP;
use DB();
use ReadConfig;

our $config = ReadConfig::get_instance();
our $SRCDIR = $config->get_option('SRCDIR');

my $debug = 0;
my $opt = shift;
if ($opt && $opt =~ /\-D/) {
  $debug = 1;
}
##########################################


# connect to slave database
my $slave_dbh = DB->db_connect('slave', 'st_spool');

# connect to master database
my $master_dbh = DB->db_connect('master', 'st_spool');

my $total = 0;

foreach my $letter ('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','misc') {
  if ($debug) {
    print "doing letter: $letter... fetching spams: ";
  }
  my $sth = $slave_dbh->prepare("SELECT * FROM spam_$letter WHERE in_master='0'");
  $sth->execute() or next;
  if ($debug) {
    print $sth->rows." found\n";
  }

  while (my $row = $sth->fetchrow_hashref()) {
    # build query
    my $query = "INSERT IGNORE INTO spam_$letter SET ";
    foreach my $col (keys %{$row}) {
     my $value = $row->{$col};
     $value =~ s/'/\\'/g;
     $query .= $col."='".$value."', ";
    }
    $query =~ s/,\s*$//;

    # save in master
    my $res = $master_dbh->{dbh}->do($query);
    if (!$res) {
      if ($debug) {
        print "failed for: ".$row->{exim_id}."\n   with message: ".$master_dbh->errstr."\n   query was: $query\n";
      }
      next;
    }
    $total = $total + 1;

    # update slave record
    $query = "UPDATE spam_$letter SET in_master='1' WHERE exim_id='".$row->{exim_id}."'";
    $slave_dbh->{dbh}->do($query);
  }
  $slave_dbh->db_disconnect();
  $master_dbh->db_disconnect();
}
print "SUCCESSFULL|$total\n";
