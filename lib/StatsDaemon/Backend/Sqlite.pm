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

package StatsDaemon::Backend::Sqlite;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use threads();
use threads::shared();
use File::Copy();
use DBI();
use DBD::SQLite();
use ReadConfig();
use File::Path qw(mkpath);
use Fcntl qw(:flock SEEK_END);

my $shema = "
CREATE TABLE stat (
  date     int,
  key    varchar(100),
  value    int,
  UNIQUE (date, key)
);
";

sub new ($class, $daemon) {
  my $conf = ReadConfig::get_instance();

  my $this = {
    'class' => $class,
    'daemon' => $daemon,
    'data' => undef,
    'basepath' => $conf->get_option('VARDIR') . '/spool/spamtagger/stats',
    'dbfilename' => 'stats.sqlite',
    'history_avoid_keys' => '',
    'history_avoid_keys_a' => [],
    'template_database' => $conf->get_option('SRCDIR').'/lib/StatsDaemon/Backend/data/stat_template.sqlite'
  };

  bless $this, $class;

  foreach my $option (keys %{ $this->{daemon} }) {
  	if (defined($this->{$option})) {
  		$this->{$option} = $this->{daemon}->{$option};
  	}
  }
  foreach my $o (split(/\s*,\s*/, $this->{history_avoid_keys})) {
  	push @{$this->{history_avoid_keys_a}}, $o;
  }
  if (! -d $this->{basepath}) {
  	mkpath($this->{basepath});
  	$this->do_log("base path created: ".$this->{basepath});
  }
  $this->do_log("backend loaded", 'statsdaemon');

  $this->{data} = $StatsDaemon::data_;
  return $this;
}

sub thread_init ($this) {
  $this->do_log("backend thread initialization", 'statsdaemon');
  return;
}

sub access_flat_element ($this, $element) {
  my $value = 0;

  my ($path, $file, $base, $el_key) = $this->get_path_file_base_and_key_from_element($element);
  if (! -f $file) {
  	return $value;
  }
  my $dbh = $this->connect_to_db($file);
  if (defined($dbh)) {
  	my $current_date = sprintf(
      '%.4d%.2d%.2d',
  	  $this->{daemon}->get_current_date()->{'year'},
  	  $this->{daemon}->get_current_date()->{'month'},
  	  $this->{daemon}->get_current_date()->{'day'}
    );
  	my $query = 'SELECT value FROM stat WHERE date='.$current_date.' AND key=\''.$el_key.'\'';
  	my $res = $dbh->selectrow_hashref($query);
  	$this->{daemon}->add_stat( 'backend_read', 1 );
  	if (defined($res) && defined($res->{'value'})) {
  		$value = $res->{'value'};
  	}
  	$dbh->disconnect;
  } else {
  	$this->do_log( "Cannot connect to database: " . $file, 'statsdaemon',
      'error' );
  }
  return $value;
}

sub stabilize_flat_element ($this, $element) {
  my ($path, $file, $base, $el_key) = $this->get_path_file_base_and_key_from_element($element);
  foreach my $unwantedkey ( @{ $this->{history_avoid_keys_a} } ) {
    if ($el_key eq $unwantedkey) {
      return 'UNWANTEDKEY';
    }
  }

  if (! -d $path) {
    mkpath($path);
  }

  my $dbh = $this->connect_to_db($file);
  if (defined($dbh)) {
  	my $current_date = sprintf(
      '%.4d%.2d%.2d',
      $this->{daemon}->get_current_date()->{'year'},
      $this->{daemon}->get_current_date()->{'month'},
      $this->{daemon}->get_current_date()->{'day'}
    );
    my $query = 'REPLACE INTO stat (date,key,value) VALUES(?,?,?)';
    my $nbrows =  $dbh->do($query, undef, $current_date, $el_key, $this->{daemon}->get_element_value_by_name($element, 'value'));
    if (!defined($nbrows)) {
    	$this->do_log( "Could not update database: " . $query, 'statsdaemon', 'error' );
    }
    $dbh->disconnect;
    $this->{daemon}->add_stat( 'backend_write', 1 );
  } else {
    $this->do_log( "Cannot connect to database: " . $file, 'statsdaemon', 'error' );
    return '_CANNOTCONNECTDB';
  }

  return 'STABILIZED';
}

sub get_stats ($this, $start, $stop, $what, $data) {
  # TODO: This doesn't do anything...
  return 'OK';
}

sub announce_month_change ($this) {
  return;
}

sub do_log ($this, $message, $given_set, $priority) {
  my $msg = $this->{class}." ".$message;
  if ($this->{daemon}) {
    $this->{daemon}->do_log($msg, $given_set, $priority);
  }
  return;
}

##
sub get_path_file_base_and_key_from_element ($this, $element) {
	my @els = split(/:/, $element);
  my $key = pop @els;

  my $path = $this->{basepath}.'/'.join('/',@els);
  my $file = $path.'/'.$this->{dbfilename};
  my $base = join(':', @els);
  return (lc($path), lc($file), lc($base), lc($key));
}

sub connect_to_db ($this, $file) {
	copy($this->{template_database}, $file) unless (-f $file);

	my $dbh = DBI->connect("dbi:SQLite:dbname=".$file,"","");
	if (!$dbh) {
		$this->do_log( "Cannot create database: " . $file, 'statsdaemon',
      'error' );
		return;
	}

	return $dbh;
}
1;
