#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2018 SpamTagger <support@spamtagger.org>
#   Copyright (C) 2020 John Mertz <git@john.me.tz>
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
#   This script will add a blacklist to the database.
#   This script is intended to be used by the SpamTagger SOAP API (Soaper).
#
#   Usage:
#           add_to_blacklist.pl msg_dest msg_sender

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use DB();

my $dest = shift;
my $sender = shift;
err("DESTNOTVALID") if (not is_valid_email($dest));
err("SENDERNOTVALID") if (not is_valid_email($sender));

my $dbh = DB->db_connect('master', 'st_config') || err("CANNOTCONNECTDB");

# Remove content after plus in address so that rule applies to base address
$dest =~ s/([^\+]+)\+([^\@]+)\@(.*)/$1\@$3/;

# WWLists don't have unique indexes, check for duplicate first
my $sth = $dbh->prepare("SELECT * FROM wwlists WHERE sender = ? AND recipient = ? AND type = 'black'") || err("CANNOTSELECTDB");
$sth->execute($sender, $dest);
err("DUPLICATEENTRY") if ($sth->fetchrow_arrayref());

$sth = $dbh->prepare("INSERT INTO wwlists (sender, recipient, type, expiracy, status, comments)
  values (?, ?, 'black', '0000-00-00', 1, '[Blacklist]')");
$sth->execute($sender, $dest);
err("CANNOTINSERTDB") unless ($sth->rows() > 0);
$dbh->db_disconnect();

print("OK");
exit 0;

##########################################
sub is_valid_email ($email_str) {
  return 1 if ($email_str =~ /^\S*\@\S+\.\S+$/);
  return 0;
}

sub err ($err) {
  die $err . "\n";
}
