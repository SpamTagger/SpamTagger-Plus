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

package SpamHandler::Batch;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use SpamHandler::Message;
use Time::HiRes qw(gettimeofday tv_interval);

sub new ($class, $dir, $daemon) {
  my %timers;

  my $this = {
    spamdir => $dir,
    daemon  => $daemon,
    batchid => 0,
    %timers => (),
  };
  $this->{messages} = {};

  return 0 unless (-d $this->{spamdir});

  return bless $this, $class;
}

sub prepare_run ($this) {
  srand;
  $this->{batchid} = int( rand(1000000) );
  return 1;
}

sub get_messages_to_process ($this) {
  $this->{daemon}->profile_start('BATCHLOAD');
  chdir( $this->{spamdir} ) or return 0;
  my $SDIR;
  opendir($SDIR, '.' ) or return 0;

  my $waitingcount = 0;
  my $batchsize    = 0;
  my $maxbatchsize = $this->{daemon}->{maxbatchsize};
  while ( my $entry = readdir($SDIR) ) {
    next if ( $entry !~ m/(\S+)\.env$/ );
    $waitingcount++;
    my $id = $1;

    next if ( $batchsize >= $maxbatchsize );
    next if ( $this->{daemon}->is_locked($id) );
    if ( -f "$id.msg" ) {
      $batchsize++;
      $this->add_message($id);
    } else {
      $this->{daemon}->do_log(
        $this->{batchid}.": NOTICE: message $id has envelope file but no body...",
        'spamhandler'
      );
    }
  }

  if ( $waitingcount > 0 ) {
    $this->{daemon}->do_log(
      $this->{batchid} . ": "
        . $waitingcount
        . " messages waiting, taken "
        . keys %{ $this->{messages} },
      'spamhandler', 'debug'
    );
  } else {
    $this->{daemon}->do_log(
      $this->{batchid} . ": "
        . $waitingcount
        . " messages waiting, taken "
        . keys %{ $this->{messages} },
      'spamhandler', 'debug'
    );
  }
  closedir($SDIR);
  my $btime = $this->{daemon}->profile_stop('BATCHLOAD');
  $this->{daemon}
    ->do_log( $this->{batchid} . ": finished batch loading in $btime seconds",
    'spamhandler', 'debug' );
  return 1;
}

sub add_message ($this, $id) {
  $this->{daemon}->add_lock($id);
  $this->{messages}{$id} = $id;
  return;
}

sub run ($this) {
  $this->{daemon}->profile_start('BATCHRUN');
  my $nbmsgs = keys %{ $this->{messages} };

  my $t   = threads->self;
  my $tid = $t->tid;

  return if ( $nbmsgs < 1 );
  $this->{daemon}->do_log( $this->{batchid} . ": starting batch run",
    'spamhandler', 'debug' );
  my $count = 0;
  foreach my $msgid ( keys %{ $this->{messages} } ) {
    $count++;
    $this->{daemon}->do_log(
      "($tid) "
        . $this->{batchid}
        . ": processing message: $msgid ($count/$nbmsgs)",
      'spamhandler', 'debug'
    );

    my $msg = SpamHandler::Message->new($msgid, $this->{daemon},$this->{batchid} );
    $msg->load();
    $msg->process();

    ## then log
    my %prepared = %{ $this->{daemon}->{prepared} };
    my $inmaster = 0;
    foreach my $dbname ( keys %prepared ) {
      $msg->do_log( $dbname, \$inmaster );
    }
    $msg->purge();
    my $msgtimers = $msg->get_timers();
    $this->add_timers($msgtimers);
  }
  delete $this->{messages};

  $this->start_timer('Batch logging message');
  foreach my $dbname ( keys %{ $this->{daemon}->{dbs} } ) {
    if ( $this->{daemon}->{dbs}{$dbname} ) {
      $this->{daemon}->{dbs}{$dbname}->commit();
    }
  }
  $this->end_timer('Batch logging message');
  $this->log_timers();
  my $btime = $this->{daemon}->profile_stop('BATCHRUN');
  $this->{daemon}->do_log(
    $this->{batchid}
      . ": finished batch run in $btime seconds for "
      . $nbmsgs
      . " messages",
    'spamhandler', 'debug'
  );
  return;
}

sub add_timers ($this, $msgtimers) {
  my %timers = %{$msgtimers};
  foreach my $t ( keys %timers ) {
    next if ( $t !~ m/^d_/ );
    $this->{'timers'}{$t} += $timers{$t};
  }
  return 1;
}

#######
## profiling timers
sub start_timer ($this, $timer) {
  $this->{'timers'}{$timer} = [gettimeofday];
  return;
}

sub end_timer ($this, $timer) {
  my $interval = tv_interval( $this->{timers}{$timer} );
  $this->{'timers'}{ 'd_' . $timer } = ( int( $interval * 10000 ) / 10000 );
  return;
}

sub get_timers ($this) {
  return $this->{'timers'};
}

sub log_timers ($this) {
  foreach my $t ( keys %{ $this->{'timers'} } ) {
    next if ( $t !~ m/^d_/ );
    my $tn = $t;
    $tn =~ s/^d_//;
    $this->{daemon}->do_log(
      'Batch spent ' . $this->{'timers'}{$t} . "s. in " . $tn, 'spamhandler', 'debug'
    );
  }
  return;
}

1;
