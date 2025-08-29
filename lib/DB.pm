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

sub db_connect ($class, $type, $db, $critical_p = 0) {
  my $critical = 1;
  $critical = 0 if ($critical_p < 1);
  if (!$type || $type !~ /slave|master|realmaster|custom/) {
  	print "BADCONNECTIONTYPE\n";
    return "";
  }
  my $dbase = 'st_config';
  $dbase = $db if ($db);

  # determine socket to use
  my $conf = ReadConfig::get_instance();
  my $socket = $conf->get_option('VARDIR')."/run/mysql_master/mysqld.sock";
  $socket = $conf->get_option('VARDIR')."/run/mysql_slave/mysqld.sock" if ($type =~ /slave/);

  my $dbh;
  my $realmaster = 0;
  my $masterfile = $conf->get_option('VARDIR')."/spool/spamtagger/master.conf";
  if ( ($type =~ /realmaster/ && -f $masterfile) || $type =~ /custom/) {
  	my $host;
  	my $port;
  	my $password;
    my $MASTERFILE;
    if (open($MASTERFILE, '<', $masterfile)) {
      while (<$MASTERFILE>) {
        if (/HOST (\S+)/) { $host = $1; }
        if (/PORT (\S+)/) { $port = $1; }
        if (/PASS (\S+)/) { $password = $1; }
      }
      close $MASTERFILE;
    }
    if ($type =~ /custom/) {
      $host = $db->{'host'};
      $port = $db->{'port'};
      $password = $db->{'password'};
      $dbase = $db->{'database'};
    }
    if (! ( $host eq "" || $port eq "" || $password eq "") ) {
      $dbh = DBI->connect("DBI:mysql:database=$dbase;host=$host:$port;",
			  "spamtagger", $password, {RaiseError => 0, PrintError => 0, AutoCommit => 1}
      )	or fatal_error("CANNOTCONNECTDB", $critical);
      $realmaster = 1;
    }
  }
  if ($realmaster < 1) {
    $dbh = DBI->connect("DBI:mysql:database=$db;host=localhost;mysql_socket=$socket",
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
  return $this->{dbh};
}

sub ping ($this) {
  return $this->{dbh}->ping() if (defined($this->{dbh}));
  return 0;
}

sub db_disconnect ($this) {
  my $dbh = $this->{dbh};
  $dbh->disconnect() if ($dbh);
  $this->{dbh} = "";
  return 1;
}

sub fatal_error ($msg, $critical = 0) {
  return 0 if ($critical < 1);
  print $msg."\n";
  exit(0);
}

sub prepare ($this, $query) {
  my $dbh = $this->{dbh};

  my $prepared = $dbh->prepare($query);
  unless ($prepared) {
    print "WARNING, CANNOT EXECUTE ($query => ".$dbh->errstr.")\n";
    return 0;
  }
  return $prepared;
}

sub execute ($this, $query, $nolock = 0) {
  my $dbh = $this->{dbh};

  unless (defined($dbh)) {
  	print "WARNING, DB HANDLE IS NULL\n";
    return 0;
  }
  unless ($dbh->do($query)) {
    print "WARNING, CANNOT EXECUTE ($query => ".$dbh->errstr.")\n";
    return 0;
  }
  return 1;
}

sub commit ($this, $query) {
  my $dbh = $this->{dbh};

  unless ($dbh->commit()) {
    print "WARNING, CANNOT commit\n";
    return 0;
  }
  return 1;
}

sub get_list_of_hash ($this, $query, $nowarnings = 0) {
  my $dbh = $this->{dbh};
  my @results;

  my $sth = $dbh->prepare($query);
  my $res = $sth->execute();
  if (!defined($res)) {
  	if (! $nowarnings) {
      print "WARNING, CANNOT QUERY ($query => ".$dbh->errstr.")\n";
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
  my $dbh = $this->{dbh};
  my @results;

  my $sth = $dbh->prepare($query);
  my $res = $sth->execute();
  if (!defined($res)) {
  	if (! $nowarnings) {
      print "WARNING, CANNOT QUERY ($query => ".$dbh->errstr.")\n";
  	}
    return @results;
  }
  while (my @ref = $sth->fetchrow_array()) {
    push @results, $ref[0];
  }

  $sth->finish();
  return @results;
}

sub get_count ($this, $query) {
  my $dbh = $this->{dbh};
  my $sth = $dbh->prepare($query);
  my $res = $sth->execute();

  my ($count) = $sth->fetchrow_array;

  return($count);
}

sub get_hash_row ($this, $query, $nowarnings = 0) {
  my $dbh = $this->{dbh};
  my %results;

  my $sth = $dbh->prepare($query);
  my $res = $sth->execute();
  unless (defined($res)) {
  	unless ($nowarnings) {
      print "WARNING, CANNOT QUERY ($query => ".$dbh->errstr.")\n";
  	}
    return %results;
  }

  my $ret = $sth->fetchrow_hashref();
  $results{$_} = $ret->{$_} foreach (keys(%{$ret}));
  
  $sth->finish();
  return %results;
}

sub get_last_id ($this) {
  my $res = 0;
  my $query = "SELECT LAST_INSERT_ID() as lid;";

  my $sth = $this->{dbh}->prepare($query);
  my $ret = $sth->execute();
  return $res unless ($ret);
  
  $ret = $sth->fetchrow_hashref();
  return $res unless (defined($ret));

  return $ret->{'lid'} if (defined($ret->{'lid'}));
  return $res;
}

sub get_error ($this) {
  my $dbh = $this->{dbh};

  return $dbh->errstr if (defined($dbh->errstr));
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

1;
