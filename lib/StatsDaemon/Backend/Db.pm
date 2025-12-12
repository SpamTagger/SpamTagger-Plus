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

package StatsDaemon::Backend::Db;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use threads();
use threads::shared();
use lib '/usr/spamtagger/lib';
use DB();

my $_current_table : shared = '';
my $_current_table_exists : shared = 0;
my $_current_table_creating : shared = 0;

sub new ($class, $daemon) {
  my $this = {
    'class' => $class,
    'daemon' => $daemon
  };
  bless $this, $class;

   foreach my $option (keys %{ $this->{daemon} }) {
     if (defined($this->{$option})) {
       $this->{$option} = $this->{daemon}->{$option};
     }
  }

  $this->do_log("backend loaded", 'statsdaemon');

  use StatsDaemon;
  my $statsdaemon = StatsDaemon->new();
  $this->{data} = $statsdaemon->{data_};
  return $this;
}

sub thread_init ($this) {
  $this->do_log("backend thread initialization", 'statsdaemon');
  $this->connect_backend();
  return;
}

sub access_flat_element ($this, $element) {
  my $value = 0;

  if ( $_current_table_exists ) {
      my $query =
        "SELECT s.id as id, d.value as value FROM "
        . $_current_table
        . " d, stats_subject s WHERE s.id=d.subject AND s.subject='"
        . $element
        . "' AND d.day="
        . $this->{daemon}->get_current_date()->{'day'};
      $this->{daemon}->add_stat( 'backend_read', 1 );
      return '_NOBACKEND' if ( !$this->connect_backend() );
      my %res = $this->{db}->get_hash_row($query);
      $this->do_log( 'Query executed: '.$query, 'statsdaemon', 'debug');
      if ( $res{'id'} && $res{'value'} ) {

        $this->{data}->{$element}->{'stable_id'} = $res{'id'};

        $value = $res{'value'};
      }
      $this->do_log( 'loaded data for ' . $element . ' from backend',
        'statsdaemon', 'debug' );
   }
   return $value;
}

sub stabilize_flat_element ($this, $element) {
  my $table = '';
  if ( $_current_table_exists ) {
    $table = $_current_table;
  } else {
    if ( $this->create_current_table() ) {
      $table = $_current_table;
    }
  }
  if ( $table eq '' ) {
    $this->do_log(
      "Error: Current table cannot be found (probably being created)",
      'statsdaemon', 'error' );
    return '_CANNOTSTABILIZE';
  }
  my $day = $this->{daemon}->get_current_date()->{'day'};

  ## find out if element already is registered, register it if not.
  if (!defined($this->{data}->{$element}) ||
     !defined($this->{data}->{$element}->{'stable_id'}) ||
     (defined($this->{data}->{$element}->{'stable_id'}) && !$this->{data}->{$element}->{'stable_id'})
     ) {
    my $query =
      "SELECT id FROM stats_subject WHERE subject='" . $element . "'";
    $this->{daemon}->add_stat( 'backend_read', 1 );
    return '_NOBACKEND' if ( !$this->connect_backend() );
    my %res = $this->{db}->get_hash_row($query);
    if ( defined( $res{'id'} ) ) {
      $this->{daemon}->set_element_value_by_name( $element, 'stable_id',
        $res{'id'} );
    } else {
      $query = "INSERT INTO stats_subject SET subject='" . $element . "'";
      return '_NOBACKEND' if ( !$this->connect_backend() );
      if ( $this->{db}->execute($query) ) {
        my $id = $this->{db}->get_last_id();
        $this->{daemon}->add_stat( 'backend_write', 1 );
        if ($id) {
          $this->{daemon}->set_element_value_by_name( $element, 'stable_id',
            $id );
          $this->do_log(
            'registered new element ' . $element
              . ' in backend with id '
              . $id,
            'statsdaemon', 'debug'
          );
        } else {
          $this->do_log(
            "Could not get subject ID for element: $element",
            'statsdaemon', 'error' );
        }
      } else {
        ## maybe inserted meanwhile, so search again...
        $query =
          "SELECT id FROM stats_subject WHERE subject='" . $element
          . "'";
        $this->{daemon}->add_stat( 'backend_read', 1 );
        return '_NOBACKEND' if ( !$this->connect_backend() );
        %res = $this->{db}->get_hash_row($query);
        if ( defined( $res{'id'} ) ) {
          $this->{daemon}->set_element_value_by_name( $element, 'stable_id',
            $res{'id'} );
        } else {
          $this->do_log(
            "Could not insert subject for element: $element",
            'statsdaemon', 'error' );
        }
      }
    }
  }

  ## update or insert the value
  my $query =
    "INSERT INTO " . $table
    . " SET day="
    . $day
    . ", subject="
    . $this->{daemon}->get_element_value_by_name($element, 'stable_id')
    . ", value="
    . $this->{daemon}->get_element_value_by_name($element, 'value')
    . " ON DUPLICATE KEY UPDATE value="
    . $this->{daemon}->get_element_value_by_name($element, 'value');
  return '_NOBACKEND' if ( !$this->connect_backend() );
  if ( !$this->{db}->execute($query) ) {
    $this->do_log( "Could not stabilize statistic with query: '$query'",
      'statsdaemon', 'error' );
    return '_CANNOTSTABILIZE';
  }
  $this->{daemon}->add_stat( 'backend_write', 1 );
  $this->do_log( 'stabilized value for element ' . $element . ' in backend',
    'statsdaemon', 'debug' );
  return 'STABILIZED';
}

sub get_stats ($this, $start, $stop, $what, $data) {
  ## defs
  my $base_subject = '---';

  if ( $start !~ /(\d{4})(\d{2})(\d{2})/ ) {
    return '_BADSTARTDATE';
  }
  my $start_table = $1 . $2;
  my $start_y   = $1;
  my $start_m   = $2;
  my $start_day   = $3;
  if ( $stop !~ /(\d{4})(\d{2})(\d{2})/ ) {
    return '_BADSTOPDATE';
  }
  my $stop_table = $1 . $2;
  my $stop_day   = $3;

  my $day_table_y = $start_y;
  my $day_table_m = $start_m;

## get backend table to use
  my $day_table = sprintf '%.4u%.2u', $day_table_y, $day_table_m;
  my @tables;
  while ( $day_table <= $stop_table ) {
    $day_table_m++;
    push @tables, $day_table;

    if ( $day_table_m > 12 ) {
      $day_table_m = 1;
      $day_table_y++;
    }
    $day_table = sprintf '%.4u%.2u', $day_table_y, $day_table_m;
  }

## get subjects to work on
  my @subjects;
  foreach my $what ( split /,/, $what ) {
    my %sub;
    if ( $what !~ /\*/ ) {
      if ( $what =~ /^(\S+)@(\S+)/ ) {
      #  $sub{'sub'} = $base_subject . ':' . $2 . ':' . $1 . ':%';
      #  $sub{'neg'} = $sub{'sub'} . ':%';
         $sub{'sub'} = 'user:'.$2.':'.$1.':%';
      } elsif ( $what eq "_global" ) {
      #  $sub{'sub'} = $base_subject . ":%";
      #  $sub{'neg'} = $sub{'sub'} . ':%';
         $sub{'sub'} ='global:%';
      } else {
      #  $sub{'sub'} = $base_subject . ':' . $what . ":%";
      #  $sub{'neg'} = $sub{'sub'} . ':%';
         $sub{'sub'} = 'domain:'.$what.":%";
      }
    } else {

      # find all subjects for * queries
      if ( $what =~ /^\*@(\S+)/ ) {
        my $dom = $1;
        ## push domain itself
        my %dsub;
        #$dsub{'sub'} = $base_subject . ':' . $dom . ':%';
        #$dsub{'neg'} = $dsub{'sub'} . ':%';
        $dsub{'sub'} = 'domain:'.$dom.':%';

        push @subjects, \%dsub;

        ## then subject
        #$sub{'sub'} = $base_subject . ':' . $dom . ':%:%';
        #$sub{'neg'} = $sub{'sub'} . ':%';
        $sub{'sub'} = 'user:'.$dom.":%";
      } else {
        ## push global
        my %gsub;
        #$gsub{'sub'} = $base_subject . ":%";
        #$gsub{'neg'} = $gsub{'sub'} . ':%';
        $gsub{'sub'} = 'global:%';
        push @subjects, \%gsub;

        ## then subject
        #$sub{'sub'} = $base_subject . ':%:%';
        #$sub{'neg'} = $sub{'sub'} . ':%';
        $sub{'sub'} = 'domain:%';
      }
    }
    push @subjects, \%sub;
  }

## query each subject through each table and compute stats
  foreach my $subh (@subjects) {

    my %sub     = %{$subh};
    my $table_idx = 0;
    foreach my $table (@tables) {
      my $day_where = '';
      if ( $table_idx == 0 ) {
        $day_where = " AND d.day >= " . $start_day;
      }
      $table_idx++;
      if ( $table_idx == @tables ) {
        $day_where = " AND d.day <= " . $stop_day;
      }
      if ( @tables == 1 ) {
        $day_where =
          " AND d.day >= " . $start_day . " AND d.day <= " . $stop_day;
      }

      foreach my $func ( 'SUM', 'MAX' ) {
        my $query =
          "SELECT s.subject, " . $func
          . "(d.value) sm FROM stats_subject s LEFT JOIN stats_$table d ON ";
        $query .= "d.subject=s.id ";
        $query .= $day_where
          ;  ## thanks Raf for this one ! Major speed improvement
        #$query .= " WHERE ( s.subject NOT LIKE '" . $sub{'neg'} . "' ";
        #$query .= "AND s.subject LIKE '" . $sub{'sub'} . "' ";
        #if ( $func eq 'SUM' ) {
        #  $query .=
#"AND s.subject NOT LIKE '%domain' AND s.subject NOT LIKE '%user' ) ";
#        }
#        else {
#          $query .=
#"AND ( s.subject LIKE '%domain' OR s.subject LIKE '%user' ) ) ";
#        }

        $query .= " WHERE s.subject LIKE '" . $sub{'sub'} . "' ";
        if ( $func eq 'SUM' ) {
           $query .=   "AND s.subject NOT LIKE '%domain' AND s.subject NOT LIKE '%user' ";
        } else {
           $query .=  "AND ( s.subject LIKE '%domain' OR s.subject LIKE '%user' ) ";
        }

        $query .= " group by d.subject";
        $this->do_log( 'Using query: "'.$query.'"', 'statsdaemon', 'debug' );
        $this->{daemon}->increase_long_read();
        my @results = $this->{db}->get_list_of_hash( $query, 1 );
        $this->{daemon}->decrease_long_read();
        foreach my $res (@results) {
          if ( !$res->{'sm'} ) {
            $res->{'sm'} = 0;
          }
          my @subject_path = split( ':', $res->{'subject'} );
          my $value_key  = pop @subject_path;
          my $subject_key  = join( ':', @subject_path );
          if ( !defined( $data->{$subject_key}{$value_key} ) ) {
            $data->{$subject_key}{$value_key} = 0;
          }
          if ( $func eq 'MAX' ) {
            if ( $res->{'sm'} > $data->{$subject_key}{$value_key} ) {
              $data->{$subject_key}{$value_key} = $res->{'sm'};
            }
          } else {
            $data->{$subject_key}{$value_key} += $res->{'sm'};
          }
        }
      }
    }
  }
  return 'OK';
}

sub announce_month_change ($this) {
  $_current_table_exists = 0;
  return;
}

## Database management
sub connect_backend ($this) {
  return 1 if ( defined( $this->{db} ) && $this->{db}->ping() );

  $this->{db} = DB->db_connect( 'replica', 'st_stats', 0 );
  if ( !$this->{db}->ping() ) {
    $this->do_log( "WARNING, could not connect to statistics database",
      'statsdaemon', 'error' );
    return 0;
  }
  $this->do_log( "Connected to statistics database", 'statsdaemon' );

  if ( $_current_table_exists == 0 ) {
    $this->create_current_table();
  }

  my $query = "SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED";
  $this->{db}->execute($query);

  return 1;
}

sub create_current_table($this) {

  if ( $_current_table_creating == 1 ) {
    return 0;
  }
  $_current_table_creating = 1;

  my $query =
    "CREATE TABLE IF NOT EXISTS `stats_subject` ("
    . "`id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,"
    . "`subject` varchar(250) DEFAULT NULL,"
    . "UNIQUE KEY `subject` (`subject`),"
    . "KEY `id` (`id`)"
    . ") ENGINE=MyISAM";
  if ( !$this->{db}->execute($query) ) {
    $this->do_log( "Cannot create subject table", 'statsdaemon', 'error' );
    $_current_table_creating = 0;
    return 0;
  }

  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
    localtime time;
  %{$this->{daemon}->get_current_date()} =
    ( 'day' => $mday, 'month' => $mon + 1, 'year' => $year + 1900 );
  my $table = "stats_"
    . sprintf( '%.4d%.2d', $this->{daemon}->get_current_date()->{'year'}, $this->{daemon}->get_current_date()->{'month'} );

  $query =
    "CREATE TABLE IF NOT EXISTS `$table` ("
    . "`day` tinyint(4) UNSIGNED NOT NULL, "
    . "`subject` int(11) UNSIGNED NOT NULL, "
    . "`value` BIGINT UNSIGNED NOT NULL DEFAULT '0', "
    . "PRIMARY KEY `day` (`day`,`subject`), "
    . "KEY `subject_idx` (`subject`) "
    . ") ENGINE=MyISAM";
  $this->{daemon}->add_stat( 'backend_write', 1 );
  if ( !$this->{db}->execute($query) ) {
    $this->do_log( "Cannot create table: " . $table, 'statsdaemon',
      'error' );
    $_current_table_creating = 0;
    return 0;
  } else {
    $this->do_log( 'Table ' . $table . " created", 'statsdaemon' );
  }
  $_current_table_exists = 1;
  $_current_table = $table;
  $_current_table_creating = 0;
  return 1;
}

sub do_log ($this, $message, $given_set, $priority) {
  my $msg = $this->{class}." ".$message;
  $this->{daemon}->do_log($msg, $given_set, $priority) if ($this->{daemon});
  return;
}

1;
