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
#   This module will wait for spam quarantined and log them in databases
#

package SpamLogger;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use DB();

use parent qw(UDPDaemon);

use POSIX();
use Sys::Hostname();
use Socket();
use MIME::Base64();

my @fields = ('id', 'tolocal', 'todomain', 'sender', 'subject', 'score', 'rbls', 'prefilter', 'globalscore');

sub new ($class, $name, $file) {
  my $this = $class->SUPER::create($class, $name, $file);

  my $conf = ReadConfig::get_instance();
  $this->{slaveID} = $conf->get_option('HOSTID');
  bless $this, $class;
  return $this;
}

sub process_datas ($this, $datas) {
  if ($datas =~ /^LOG (.*)/) {
    my $tmp = $1;
    my @gotfields = split "_", $tmp;
    my %msg;
    my $i = 0;
    foreach my $field (@fields) {
      if (defined($gotfields[$i])) {
        $msg{$field} = decode_base64($gotfields[$i]);
        # some cleanup
        $msg{$field} =~ s/\\//g;
        $msg{$field} =~ s/'/\\'/g;
        $i++;
      } else {
        $msg{$field} = "";
      }
    }

    if (!defined($msg{id})) {
      $this->log_message("WARNING ! no id found for message ($tmp)");
      next;
    }
    my $logged_in_master = $this->log_in_master(\%msg);
    if (!$logged_in_master) {
      $this->log_message("Message ".$msg{id}." cannot be logged in master DB !");
    }
    my $logged_in_slave = $this->log_in_slave($logged_in_master, \%msg);
    if (!$logged_in_slave) {
      $this->log_message("Message ".$msg{id}." cannot be logged in slave DB !");
    }

    if ($logged_in_master && $logged_in_slave) {
      $this->log_message("Message ".$msg{id}." logged both");
      return "LOGGED BOTH";
    }
    return "LOGGED $logged_in_slave $logged_in_master";
  }
  return "UNKNOWN COMMAND";
}

#####
## logSpam
#####
sub log_spam ($this) {
  my $query = "LOG";
  my $params = "";
  my %msg;
  foreach my $field (@fields) {
    $msg{$field} = shift;
    if (defined($msg{$field})) {
      my $value = encode_base64($msg{$field});
      chomp($value);
      $params .= "_".$value;
    }
  }
  $params =~ s/^_//;
  $params =~ s/^ //;
  $query .= " ".$params;
  $query =~ s/\n//g;
  my $res = $this->exec_call($query);
  return $res;
}

#####
## logInMaster
#####
sub log_in_master ($this, $message = {}) {
  unless (defined($this->{masterDB}) && $this->{masterDB}->ping()) {
    $this->{masterDB} = DB->db_connect('realmaster', 'st_spool', 0);
    return 0 unless ( defined($this->{masterDB}) && $this->{masterDB}->ping());
  }

  my $table = "misc";
  if ( $message->{tolocal} =~ /^([a-z,A-Z])/ ) {
    $table = lc($1);
  } elsif ( $message->{tolocal}  =~ /^[0-9]/ ) {
    $table = 'num';
  } else {
    $table = 'misc';
  }
  my $query =
    "INSERT IGNORE INTO spam_$table (date_in, time_in, to_domain, to_user, sender, exim_id, M_score, M_rbls, M_prefilter, M_subject, M_globalscore, forced, in_master, store_slave) ".
    "VALUES (NOW(), NOW(), '".$message->{todomain}."', '".$message->{tolocal}."', ".
    "'".$message->{sender}."', '".$message->{id}."', ".
    "'".$message->{score}."', '".$message->{rbls}."', '". $message->{prefilter}."', '".$message->{subject}."', '".$message->{globalscore}."', '0', '0', '".$this->{slaveID}."')";

  return 0 unless ($this->{masterDB}->execute($query));
  return 1;
}

#####
## logInSlave
#####
sub log_in_slave ($this, $master_stored, $message = {}) {
  my $master_stored = shift;

  if (!defined($this->{slaveDB}) || !$this->{slaveDB}->ping()) {
    $this->{slaveDB} = DB->db_connect('slave', 'st_spool', 0);
    if ( !defined($this->{slaveDB}) || !$this->{slaveDB}->ping()) { return 0; }
  }

  my $table = "misc";
  if ( $message->{tolocal} =~ /^([a-z,A-Z])/ ) {
    $table = lc($1);
  } elsif ( $message->{tolocal}  =~ /^[0-9]/ ) {
    $table = 'num';
  } else {
    $table = 'misc';
  }
  my $query =
    "INSERT IGNORE INTO spam_$table (date_in, time_in, to_domain, to_user, sender, exim_id, M_score, M_rbls, M_prefilter, M_subject, M_globalscore, forced, in_master, store_slave) ".
    "VALUES (NOW(), NOW(), '".$message->{todomain}."', '".$message->{tolocal}."', ".
    "'".$message->{sender}."', '".$message->{id}."', ".
    "'".$message->{score}."', '".$message->{rbls}."', '". $message->{prefilter}."', '".$message->{subject}."', '".$message->{globalscore}."', '0', '".$master_stored."', '".$this->{slaveID}."')";

  return 0 unless ($this->{slaveDB}->execute($query));
  return 1;
}

1;
