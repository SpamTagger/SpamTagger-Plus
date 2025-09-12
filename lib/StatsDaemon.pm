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

package StatsDaemon;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use threads();
use threads::shared();
use Time::HiRes qw(gettimeofday tv_interval);
use Digest::MD5 qw(md5_hex);
use Date::Calc qw(Add_Delta_Days Today);
use Devel::Size qw(size total_size);
use lib '/usr/spamtagger/lib';
use ReadConfig();
use DB();
use StatsClient();

use parent qw(SockTDaemon);

## define all shared data
my %stats_ : shared = (
  'queries'       => 0,
  'queries_add'     => 0,
  'queries_get'     => 0,
  'stabilize_element' => 0,
  'stabilize_all'   => 0,
  'backend_read'    => 0,
  'backend_write'   => 0
);

my %current_date_ : shared = ( 'day' => 0, 'month' => 0, 'year' => 0 );
my %backend_infos_ : shared = (
  'current_table'      => '',
  'current_table_exists'   => 0,
  'current_table_creating' => 0,
  'stabilizing'      => 0,
  'long_read'        => 0
);
my $closing_ : shared       = 0;
my $clearing_ : shared      = 0;
my $changing_day_ : shared    = 0;
my $last_stable_ : shared     = 0;
my $set_socks_available_ : shared = 0;

sub new ($class, $myspec_this) {
  my $conf = ReadConfig::get_instance();

  my $spec_this = {
    name        => 'StatsDaemon',
    max_unstable_time      => 20,
    stabilize_every        => 60,
    purge_limit            => 0,
    reserve_set_socks      => 1,
    backend                => undef,
    socketpath             => $conf->get_option('VARDIR') . "/run/statsdaemon.sock",
    pidfile                => $conf->get_option('VARDIR') . "/run/statsdaemon.pid",
    configfile             => $conf->get_option('SRCDIR') . "/etc/spamtagger/statsdaemon.conf",
    clean_thread_exit      => 0,
    backend_type           => 'none',
    'history_avoid_keys'   => '',
    'history_avoid_keys_a' => []
  };

  # add specific options of child object
  $spec_this->{$_} = $myspec_this->{$_} foreach (keys(%{$myspec_this}));

  ## call parent class creation
  my $this = $class->SUPER::new( $spec_this->{'name'}, undef, $spec_this );
  bless $this, 'StatsDaemon';

  $this->{history_avoid_keys} =~ s/\'//gi;
  foreach my $o (split(/\s*,\s*/, $this->{history_avoid_keys})) {
    push @{$this->{history_avoid_keys_a}}, $o;
  }

  ## set startup shared variables
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
  %current_date_ = ( 'day' => $mday, 'month' => $mon + 1, 'year' => $year + 1900 );
  $set_socks_available_ = $this->{'prefork'};

  if ($this->{reserve_set_socks} >= $this->{prefork}) {
    $this->{reserve_set_socks} = $this->{prefork}-1;
  }

  my $data_ = &share( {} );
  $this->{data_} = $data_;
  return $this;
}

sub pre_fork_hook ($this) {
  my $backend_class = 'StatsDaemon::Backend::'.ucfirst($this->{backend_type});

  die('Backend type does not exists: '.$backend_class) unless (eval { "require $backend_class" });
  $this->{backend_object} = $backend_class->new($this);

  $this->SUPER::pre_fork_hook();
  return;
}

### define specific hooks
sub exit_hook ($this) {
  $this->SUPER::exit_hook();

  $this->do_log('Close called, stabilizing and cleaning data...', 'statsdaemon');
  $this->stabilize_flat_all();
  $this->do_log('Data stabilized. Can shutdown cleanly.', 'statsdaemon');

  return;
}

sub init_thread_hook ($this) {
  $this->do_log( 'StatsDaemon thread initialization...', 'statsdaemon' );
  $this->{backend_object}->thread_init();

  $last_stable_ = time();

  return;
}

sub exit_thread_hook ($this) {
  $this->do_log( 'StatsDaemon thread exiting hook...', 'statsdaemon' );
  return;
}

sub post_kill_hook ($this) {
  return;
}

sub status_hook ($this) {
  my $res = '-------------------'."\n";
  $res .= 'Current statistics:'."\n";
  $res .= '-------------------' ."\n";

  $res .= $this->SUPER::status_hook();
  my $client = StatsClient->new();
  $res .= $client->query('GETINTERNALSTATS');

  $res .= '-------------------' ."\n";

  $this->do_log($res, 'statsdaemon');

  return $res;
}

####### Main processing
sub data_read ($this, $data) {
  my $data_ = $this->{data_};

  $this->do_log(
    'Got ' . $set_socks_available_ . " available set sockets",
    'statsdaemon', 'debug'
  );

  $this->do_log( "Received datas: $data", 'statsdaemon', 'debug' );
  my $ret = 'NOTHINGDONE';

  $this->add_stat( 'queries', 1 );

  ## check if we changed day
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
  $year += 1900;
  $mon  += 1;
  if ( $year != $current_date_{'year'} || $mon != $current_date_{'month'} ) {
    $this->{backend_object}->announce_month_change();
  }
  if ( $mday != $current_date_{'day'} ) {
    if ( !$changing_day_ ) {
      $changing_day_ = 1;
      ## stabilize all and reset full %data_
      $this->do_log(
        'Day change initialized, stabilizing and clearing data...',
        'statsdaemon'
      );
      $this->stabilize_flat_all();
      $this->clear_all_data();
      $current_date_{'day'} = $mday;
      $this->do_log( 'Day change done', 'statsdaemon' );
      $changing_day_ = 0;
    } else {
      return '_RETRY';
    }
  }

  ## ADD command
  ##   ADD element value
  if ( $data =~ m/^ADD\s+(\S+)\s+(\d+)/i ) {
    my $element = $1;
    $element =~ s/'/\\'/;
    $element = lc($element);
    my $value = $2;

    my $valh = $this->access_flat_element( $element, 1 );
    $this->add_element_value( $valh, $value );
    $this->add_stat( 'queries_add', 1 );
    $this->set_element_value( $data_->{$element}, 'stable', 0 );
    $this->check_for_stabilization($element);

    ## check if its time to stabilize all
    my $time = time();
    if ( $time - $last_stable_ > $this->{'stabilize_every'} ) {
      $this->stabilize_flat_all();
    }

    return "ADDED " . $valh->{'value'};
  }

  ## GET command
  ##  GET element
  if ( $data =~ m/^GET\s+(\S+)\s*$/i ) {
    my $element = $1;
    $element =~ s/'/\\'/;
    $element = lc($element);

    my $valh = $this->access_flat_element( $element, 0 );
    $this->add_stat( 'queries_get', 1 );
    return $valh->{'value'};
  }

  ## GET what date date command
  if ( $data =~ m/^GET\s+(\S+)\s+([+-]?\d+)\s+([+-]?\d+)/i ) {
    my $element = $1;
    $element =~ s/'/\\'/;
    $element = lc($element);
    my $fromdate = $2;
    my $todate   = $3;

    if ( $set_socks_available_ > $this->{reserve_set_socks} ) {
      $set_socks_available_--;
      $ret = $this->calc_stats( $element, $fromdate, $todate );
      $set_socks_available_++;
      return $ret;
    } else {
      return '_NOSOCKAVAILABLE '.$set_socks_available_." <=> ".$this->{reserve_set_socks};
    }
  }

  ## STABILIZE command
  ##   STABILIZE [element]
  if ( $data =~ m/^STABILIZE\s*(\S+)?/i ) {
    my $element = $1;
    $element =~ s/'/\\'/;
    $element = lc($element);
    if ($element) {
      return $this->stabilize_flat_element($element);
    } else {
      return $this->stabilize_flat_all();
    }
  }

  ## DUMP data
  return $this->dump_data() if ( $data =~ m/^DUMP/i );

  ## CLEAR command
  return $this->clear_all_data() if ( $data =~ m/^CLEAR/i );

  ## GETINTERNALSTATS command
  return $this->get_stats() if ( $data =~ m/^GETINTERNALSTATS/i );

  return "_UNKNOWNCOMMAND";
}

####### StatsDaemon functions

## stats data management

sub create_element ($this, $element) {
  my $data_ = $this->{data_};

  unless ( defined( $data_->{$element} ) ) {
    $data_->{$element} = &share( {} );
    $data_->{$element}->{'stable'}      = 0;
    $data_->{$element}->{'value'}       = 0;
    $data_->{$element}->{'last_stable'} = time();
    $data_->{$element}->{'stable_id'}   = 0;
    $data_->{$element}->{'last_access'} = time();
  }
  return;
}

sub set_element_value ($this, $element, $key, $value) {
  lock($element);
  $element->{$key} = $value;
  return;
}

sub set_element_value_by_name ($this, $element, $key, $value) {
  my $data_ = $this->{data_};
  $this->set_element_value($data_->{$element}, $key, $value);
  return;
}

sub get_element_value_by_name ($this, $element, $key) {
  my $data_ = $this->{data_};
  return $data_->{$element}->{$key};
}

sub add_element_value ($this, $element, $value) {
  lock($element);
  $element->{'value'} += $value;
  return;
}

sub access_flat_element ($this, $element) {
  my $data_ = $this->{data_};
  unless  ( defined( $data_->{$element} ) ) {

    $this->create_element($element);
    lock(%{$data_->{$element}});

    ## try to load data from backend
    my $value = $this->{backend_object}->access_flat_element($element);
    if ($value =~ /[^0-9.]/) {
      $this->do_log('element '.$element. ' could not be fetched from backend, return is: ' .$value. '. Setting value to 0.',
        'statsdaemon', 'error');
      $value = 0;
    }
    $this->set_element_value($data_->{$element},'value', $value);

  }
  $this->set_element_value($data_->{$element},'last_access', time());
  return $data_->{$element};
}

sub check_for_stabilization ($this, $element) {
  my $data_ = $this->{data_};

  my $time = time();
  if (defined($data_->{$element}->{'last_stable'})) {
    if ( $time - $data_->{$element}->{'last_stable'} >
      $this->{'max_unstable_time'} )
    {
      $this->stabilize_flat_element($element);
      return 1;
    }
  }
  return 0;
}

sub stabilize_flat_element ($this, $element) {
  foreach my $unwantedkey ( @{ $this->{history_avoid_keys_a} } ) {
    return 'UNWANTEDKEY' if ($element =~ m/\:$unwantedkey$/);
  }
  my $data_ = $this->{data_};

  if ($this->get_long_read_count() > 0 ) {
    $this->do_log('Delaying stabilization because long read is running', 'statsdaemon');
    return '_LONGREADRUNNING';
  }
  $this->add_stat( 'stabilize_element', 1 );

  if ( defined($data_->{$element}->{'stable'}) && $data_->{$element}->{'stable'} > 0 && !$changing_day_) {
    $this->set_element_value( $data_->{$element}, 'stable_id',    1 );
    $this->set_element_value( $data_->{$element}, 'last_stable', time() );
    $this->set_element_value( $data_->{$element}, 'last_access', time() );

    $this->do_log(
      'not stabilizing value for element ' . $element . ' in backend because already stable',
      'statsdaemon', 'debug'
    );
    return 'ALREADYSTABLE';
  }

  my $stret = $this->{backend_object}->stabilizeFlat_element($element);

  return $stret if ($stret =~ /^_/);

  $this->set_element_value( $data_->{$element}, 'stable',    1 );
  $this->set_element_value( $data_->{$element}, 'last_stable', time() );
  $this->set_element_value( $data_->{$element}, 'last_access', time() );

  return $stret;
}

sub stabilize_flat_all ($this) {
  my $data_ = $this->{data_};
  my $start_time = [gettimeofday];
  return 'ALREADYSTABILIZING' if ( $backend_infos_{'stabilizing'} > 0 );

  if ($this->get_long_read_count() > 0 ) {
    $this->do_log('Delaying stabilization because long read is running', 'statsdaemon', 'debug');
    return '_LONGREADRUNNING';
  }

  $backend_infos_{'stabilizing'} = 1;
  $this->add_stat( 'stabilize_all', 1 );
  my $more = '';
  $more = ' (changing day)' if ($changing_day_ > 0);
  $this->do_log(
    'Started stabilization of all data'.$more.'...',
    'statsdaemon'
  );

  my $stcount = 0;
  my $unwantedcount = 0;
  my $errorcount = 0;
  my $purgedcount = 0;
  my $elcount = 0;
  my $stablecount = 0;
  while( my ($el, $value) = each(%{$data_})) {
    $elcount++;
    $this->do_log( 'Testing element ' . $el, 'statsdaemon', 'debug' );
    if ( !defined($data_->{$el}->{'stable'}) || $changing_day_
      || (defined($data_->{$el}->{'stable'}) && !$data_->{$el}->{'stable'} ))
    {
      my $stret = $this->stabilize_flat_element($el);
      if ($stret eq 'STABILIZED') {
        $stcount++;
      } elsif ($stret eq 'ALREADYSTABLE') {
        $stablecount++;
      } elsif ($stret eq 'UNWANTED') {
         $unwantedcount++;
      } elsif ($stret =~ /^_/) {
         $errorcount++;
      }
    } else {
       $stablecount++;
       if (defined($data_->{$el}->{'last_access'})) {
         lock(%{$data_->{$el}});
         my $delta = time() - $data_->{$el}->{'last_access'};
         if ($this->{purge_limit} && $delta > $this->{purge_limit} && $data_->{$el}->{'stable'}) {
           $this->do_log('Purging element '.$el, 'statsdaemon', 'debug');
           my $stret = $this->stabilize_flat_element($el);
           if ($stret !~ /^_/) {
             my $fret = $this->free_element($el);
             if ($fret eq 'OK') {
               $purgedcount++;
             } else {
               $errorcount++;
             }
           }
         }
       }
    }
  }

  my $interval = tv_interval($start_time);
  my $sttime = ( int( $interval * 10000 ) / 10000 );
  $this->do_log(
    'Finished stabilization of all data ('.$elcount.' elements, '.$stablecount.' stable, '.$stcount.' stabilized, '.$unwantedcount.' unwanted, '.$errorcount.' errors, '.$purgedcount.' purged in '.$sttime.' s.)',
    'statsdaemon'
  );
  $last_stable_ = time();
  $backend_infos_{'stabilizing'} = 0;
  return 'ALLSTABILIZED';
}

sub clear_all_data ($this) {
  return if ( $clearing_ > 0 );

  my $data_ = $this->{data_};

  $this->do_log( 'Started clearing of all data...', 'statsdaemon' );
  $clearing_ = 1;
  lock %{$data_};
  while( my ($el, $value) = each(%{$data_})) {
    $data_->{$el}->{'value'}  = 0;
    $data_->{$el}->{'stable'} = 0;
  }
  $clearing_ = 0;
  $this->do_log( 'Finished clearing of all data.', 'statsdaemon' );
  return 'CLEARED';
}

sub free_element ($this, $element) {
  my $data_ = $this->{data_};

  return '_UNDEF' if (!defined($data_->{$element}));

  lock %{$data_->{$element}};
  foreach my $key (keys %{$data_->{$element}}) {
    undef($data_->{$element}->{$key});
    delete($data_->{$element}->{$key});
  }
  lock %{$data_};
  $data_->{$element} = ();

  undef($data_->{$element});
  delete($data_->{$element});
  return 'OK';
}

sub dump_data ($this) {
  my $data_ = $this->{data_};

  while( my ($el, $value) = each(%{$data_})) {
    $this->do_log(' - '.$el, 'statsdaemon');
  }
  return;
}

sub calc_stats ($this, $what, $begin, $end) {
  return '_BADUSAGEWHAT' if ( !defined($what) || $what !~ m/^[a-zA-Z0-9@._\-,*:]+$/ );
  return '_BADUSAGEBEGIN' if ( !defined($begin) || $begin !~ m/^[+-]?\d{1,8}$/ );
  return '_BADUSAGEEND' if ( !defined($end) || $end !~ /^[+-]?\d{1,8}$/ );

  my %data;

  ## compute start and end dates
  my $start = `date +%Y%m%d`;
  my $stop  = $start;
  my $today = $start;
  chomp($start);
  chomp($stop);

  if ( $begin =~ /^(\d{8})/ ) {
    $start = $1;
  }
  if ( $end =~ /^(\d{8})/ ) {
    $stop = $1;
  }
  if ( $begin =~ /^([+-]\d+)/ ) {
    $start = add_date( $stop, $1 );
  }
  if ( $end =~ /^([+-]\d+)/ ) {
    $stop = add_date( $start, $1 );
  }
  if ( int($start) gt int($stop) ) {
    my $tmp = $start;
    $start = $stop;
    $stop  = $tmp;
  }
  return '_BADSTARTDATE' unless ( $start =~ /(\d{4})(\d{2})(\d{2})/ );
  return '_BADSTOPDATE' unless ( $stop !~ /(\d{4})(\d{2})(\d{2})/ );

  ## if we need today's stats, stabilize all before querying
  $this->stabilize_flat_all() if ( $stop >= $today );

  my $ret = $this->{backend_object}->get_stats($start, $stop, $what, \%data);
  return $ret if ($ret ne 'OK');

  ## return results
  return '_NODATA' if (keys %data < 1);

  my $res = '';
  foreach my $sub ( keys %data ) {
    $res .= "$sub\n";
    foreach my $key ( keys %{ $data{$sub} } ) {
      $res .= " $key: " . $data{$sub}{$key} . "\n";
    }
  }
  return $res;
}

sub increase_long_read ($this) {
  lock %backend_infos_;
  $backend_infos_{'long_read'}++;
  return;
}

sub decrease_long_read ($this) {
  lock %backend_infos_;
  $backend_infos_{'long_read'}--;
  return;
}

sub get_long_read_count ($this) {
  return $backend_infos_{'long_read'};
}

sub add_date ($in, $add) {
  return $in if ( $in !~ m/^(\d{4})(\d{2})(\d{2})$/ );
  my ( $sy, $sm, $sd ) = ( $1, $2, $3 );

  return $in if ( $add !~ m/^([\-\+])(\d+)$/ );
  my $op  = $1;
  my $delta = $2;

  my ( $fy, $fm, $fd ) = Add_Delta_Days( $sy, $sm, $sd, $op . $delta );
  my $enddate = sprintf '%.4u%.2u%.2u', $fy, $fm, $fd;
  return $enddate;
}

sub get_current_date ($this) {
  return \%current_date_;
}

sub is_changing_day ($this) {
  return $changing_day_;
}

####### Internal stats management
sub add_stat ($this, $what, $amount) {
  lock %stats_;
  $stats_{$what} = 0 unless ( defined( $stats_{$what} ) );
  $stats_{$what} += $amount;
  return 1;
}

sub get_stats ($this) {
  lock %stats_;

  my $data_ = $this->{data_};

  my $res = '  Total number of elements in memory: ' . keys( %{$data_} )."\n";
  $res .= '  Current data size: '.$this->get_data_size()."\n";
  $res .= '  Total GET queries: ' . $stats_{'queries_get'} ."\n";
  $res .= '  Total ADD queries: ' . $stats_{'queries_add'} ."\n";
  $res .= '  Total element stabilizations: ' . $stats_{'stabilize_element'}."\n";
  $res .= '  Total all stabilizations: ' . $stats_{'stabilize_all'}."\n";
  $res .= '  Total backend read: ' . $stats_{'backend_read'}."\n";
  $res .= '  Total backend write: ' . $stats_{'backend_write'}."\n";
  $res .= '  Current long read running: '.$backend_infos_{'long_read'}."\n";

  return $res;
}

sub log_stats ($this) {
  return $this->get_stats();
}

sub get_data_size ($this) {
  my $data_ = $this->{data_};
  my $size = 0;
  while( my ($el, $value) = each(%{$data_})) {
    $size += total_size($el);
  }
  return $size;
}

1;
