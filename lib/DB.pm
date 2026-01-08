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
#   This module will just read the configuration file

package DB;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use DBI();

sub db_connect ($class, $type='replica', $db='st_config', $critical_p= 0) {
  my $critical = 1;
  $critical = 0 if ($critical_p < 1);
  if ($type !~ /^replica|source|realsource|custom$/) {
    print "BADCONNECTIONTYPE\n";
    return "";
  }
  if ($db !~ /^st_config|st_spool|st_stats|dmarc_reporting$/) {
    print "BADDATABASE\n";
    return "";
  }

  # determine socket to use
  my $conf = ReadConfig::get_instance();
  my $socket = $conf->get_option('VARDIR')."/run/mariadb_source/mariadbd.sock";
  $socket = $conf->get_option('VARDIR')."/run/mariadb_replica/mariadbd.sock" if ($type =~ /replica/);

  my $dbh;
  my $realsource = 0;
  my $sourcefile = $conf->get_option('VARDIR')."/spool/spamtagger/source.conf";
  if ( ($type =~ /realsource/ && -f $sourcefile) || $type =~ /custom/) {
  	my $host;
  	my $port;
  	my $password;
    my $SOURCEFILE;
    if (open($SOURCEFILE, '<', $sourcefile)) {
      while (<$SOURCEFILE>) {
        if (/HOST (\S+)/) { $host = $1; }
        if (/PORT (\S+)/) { $port = $1; }
        if (/PASS (\S+)/) { $password = $1; }
      }
      close $SOURCEFILE;
    }
    if ($type =~ /custom/) {
      $host = $db->{'host'};
      $port = $db->{'port'};
      $password = $db->{'password'};
      $db = $db->{'database'};
    }
    if (! ( $host eq "" || $port eq "" || $password eq "") ) {
      $dbh = DBI->connect("DBI:MariaDB:database=$db;host=$host:$port;",
			  "spamtagger", $password, {RaiseError => 0, PrintError => 0, AutoCommit => 1}
      )	or fatal_error("CANNOTCONNECTDB", $critical);
      $realsource = 1;
    }
  }
  if ($realsource < 1) {
    $dbh = DBI->connect("DBI:MariaDB:database=$db;host=localhost;mariadb_socket=$socket",
			"spamtagger", $conf->get_option('MYSPAMTAGGERPWD'), {RaiseError => 0, PrintError => 0}
    ) or fatal_error("CANNOTCONNECTDB", $critical);
  }

  my $this = {
    dbh => $dbh,
    type => $type,
    critical => $critical,
  };

  return bless $this, $class;
}

sub get_type ($this) {
  return $this->{type};
}

sub ping ($this) {
  return $this->{dbh}->ping() if (defined($this->{dbh}));
  return 0;
}

sub db_disconnect ($this) {
  $this->{dbh}->disconnect() if ($this->{dbh});
  $this->{dbh} = "";
  return 1;
}

sub fatal_error ($msg, $critical = 0) {
  return 0 if ($critical < 1);
  print $msg."\n";
  exit(0);
}

sub commit ($this) {
  unless ($this->{dbh}->commit()) {
    print "WARNING, CANNOT commit\n";
    return 0;
  }
  return 1;
}

sub get_list_of_hash ($this, $query, $nowarnings = 0) {
  my @results;

  my $sth = $this->{dbh}->prepare($query);
  my $res = $sth->execute();
  if ($this->{dbh}->errstr()) {
    unless ($nowarnings) {
      print "WARNING, CANNOT QUERY ($query => ".$this->{dbh}->errstr.")\n";
    }
    return @results;
  }
  while (my $ref = $sth->fetchrow_hashref()) {
    push @results, $ref;
  }

  $sth->finish();
  return @results;
}

sub get_list ($this, $query, $nowarnings = 0) {
  my @results;

  my $sth = $this->{dbh}->prepare($query);
  my $res = $sth->execute();
  if ($this->{dbh}->errstr) {
    unless ($nowarnings) {
      print "WARNING, CANNOT QUERY ($query => ".$this->{dbh}->errstr.")\n";
    }
    return @results;
  }
  while (my $row = $sth->fetchrow_array()) {
    push @results, $row;
  }

  $sth->finish();
  return @results;
}

sub get_count ($this, $query) {
  my $sth = $this->{dbh}->prepare($query);

  my ($count) = $sth->fetchrow_array;

  return($count);
}

sub get_hash_row ($this, $query, $nowarnings = 0) {
  my %results;

  my $sth = $this->{dbh}->prepare($query);
  my $res = $sth->execute();
  if ($this->{dbh}->errstr()) {
    unless ($nowarnings) {
      print "WARNING, CANNOT QUERY ($query => ".$this->{dbh}->errstr.")\n";
    }
    return %results;
  }

  my $ret = $sth->fetchrow_hashref();
  $results{$_} = $ret->{$_} foreach (keys(%{$ret}));
  return %results;
}

sub get_last_id ($this) {
  my $query = "SELECT LAST_INSERT_ID() as lid;";

  my $sth = $this->{dbh}->prepare($query);
  my $rv = $sth->execute();
  
  my $ret = $sth->fetchrow_hashref();

  return $ret->{'lid'} if (defined($ret->{'lid'}));
  return 0;
}

sub get_error ($this) {
  return $this->{dbh}->errstr if (defined($this->{dbh}->errstr));
  return "";
}

sub set_auto_commit ($this, $v) {
  if ($v) {
    $this->{dbh}->{AutoCommit} = 1;
    return 1;
  }
  $this->{dbh}->{AutoCommit} = 0;
  return 0
}

sub execute ($this, $query) {
  my $sth = $this->{dbh}->prepare($query);
  return $sth->execute();
}

1;
