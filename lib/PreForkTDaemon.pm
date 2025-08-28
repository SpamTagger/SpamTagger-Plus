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
##  PreForkTDaemon:
##    Provides a base class of a multithreaded daemon
##
##    Hooks to be implemented by children are:
##         main_loop_hook: main thread loop, should be infinite. All thread share the same code
##         pre_fork_hook: code before threads forking, this will be global for all thread
##         post_kill_hook: code after threads are gone, typically used to clean up global stuff
##         status_hook: code expected to log or output some status data.
##    Threads termination is thrown by a TERM signal.
##    Threads signal handling should be implemented in the main_loop_hook() of the children class.

package          PreForkTDaemon;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use threads();
use threads::shared();
use POSIX();
use Sys::Syslog();
use ReadConfig();
use ConfigTemplate();
use Proc::ProcessTable();
use Time::HiRes qw(gettimeofday tv_interval);

my $PROFILE = 1;
my ( %prof_start, %prof_res ) = ();
my $daemoncounts_ = &share( {} );
my %log_prio_levels = ( 'error' => 0, 'info' => 1, 'debug' => 2 );
our $LOGGERFILE;

sub new ($class, $daemonname, $conffilepath, $spec_this = {}) {
  $daemoncounts_->{'starttime'} = time();

  my $conf = ReadConfig::get_instance();
  if ( !$daemonname ) {
    $daemonname = 'defautThreadedDaemon';
  }
  unless (defined($conffilepath)) {
    $conffilepath = 'etc/spamtagger/' . $daemonname . ".cf";
  }
  my $configfile;
  $configfile = $conf->get_option('SRCDIR') . "/" . $conffilepath unless ($conffilepath =~ /^\//);

  ## default values
  my $pidfile = $conf->get_option('VARDIR') . "/run/$daemonname.pid";
  my $logfile = $conf->get_option('VARDIR') . "/log/spamtagger/$daemonname.log";
  my $prefork = 5;
  my $debug   = 0;
  my $leaving = 0;

  my $this = {
    name                 => $daemonname,
    prefork              => $prefork,
    allthreadsrestartin  => 10,
    interval             => 3,
    daemonize            => 1,
    pidfile              => $pidfile,
    configfile           => $configfile,
    uid                  => 0,
    runasuser            => '',
    gid                  => 0,
    runasgroup           => '',
    syslog_progname      => '',
    syslog_facility      => '',
    debug                => $debug,
    clean_thread_exit    => 1,
    log_sets             => 'all',
    log_priority         => 'info',
    logfile              => $logfile,
    time_before_hardkill => 5,
    pidfile              => $pidfile
  };

  # add specific options of child object
  foreach my $sk ( keys %spec_this ) {
    $this->{$sk} = $spec_this{$sk};
  }

  ## add log_sets
  foreach my $set ( split( /,/, $this->{log_sets} ) ) {
    push @{ $this->{'logged_sets'} }, $set;
  }

  bless $this, $class;

  # do we need to dump configuration
  my $file  = $this->{configfile};
  my $tfile = $file . "_template";
  if ( -f $tfile ) {
    my $template = ConfigTemplate->new( $tfile, $file );
    my $ret = $template->dump_file();
  }

  # replace with configuration file values
  if (open(my $CONFFILE, '<', $this->{configfile})) {
    while (<$CONFFILE>) {
      chomp;
      next if /^\#/;
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $this->{$1} = $2;
      }
    }
    close $CONFFILE;
  }

  ## make sure we have the correct owners for critical files:
  foreach my $file (('pidfile', 'logfile', 'socketpath')) {
    if (defined($this->{$file}) && -f $this->{$file}) {
      my $uid = getpwnam( $this->{'runasuser'});
      my $gid = getgrnam( $this->{'runasgroup'});
      chown $uid, $gid, $this->{$file};
    }
  }

  $this->{log_prio_level} = $log_prio_levels{ $this->{log_priority} };

  $this->{'uid'} =
    $this->{'runasuser'} ? getpwnam( $this->{'runasuser'} ) : 0;
  $this->{'gid'} =
    $this->{'runasgroup'} ? getgrnam( $this->{'runasgroup'} ) : 0;

  ## set our process name
  $0 = $this->{name};
  if ( $this->{'syslog_progname'} eq '' ) {
    $this->{'syslog_progname'} = $this->{name};
  }

  ## init syslog if required
  if ( $this->{'syslog_facility'} ne '' ) {
    openlog( $this->{'syslog_progname'},
      'ndelay,pid,nofatal', $this->{'syslog_facility'} );
      $this->{'do_syslog'} = 1;
  }
  return $this;
}

sub init_daemon ($this) {
  my $result = 'not started';
  my @errors;

  ## change user and group if needed
  if ( $this->{'gid'} ) {
    ( $(, $) ) = ( $this->{'gid'}, $this->{'gid'} );
    $( == $this->{'gid'} && $) == $this->{'gid'}
      || die "Can't set GID " . $this->{'gid'};
    $) = $this->{'gid'};
  }
  if ( $this->{'uid'} ) {
    ( $<, $> ) = ( $this->{'uid'}, $this->{'uid'} );
    $< == $this->{'uid'} && $> == $this->{'uid'}
      || die "Can't set UID " . $this->{'uid'};
  }
  $this->do_log(
    'Set UID to ' . $this->{'runasgroup'} . "(" . $< . ")",
    'daemon'
  );
  $this->do_log(
    'Set GID to ' . $this->{'runasgroup'} . "(" . $( . ")",
    'daemon'
  );

  my @pids = $this->read_pid_file();

  require Proc::ProcessTable;
  my $t = Proc::ProcessTable->new();
  my $match = 0;
  my @errors;
  foreach my $p ( @{ $t->table } ) {
    my $cmndline = $p->{'cmndline'};
    $cmndline =~ s/\s*$//g;
    if ($cmndline eq $this->{'name'}) {
      if ($p->{'pid'} == $$) {
        next;
      } elsif (grep { /$p->{'pid'}/ } @pids) {
        $match = $p->{'pid'};
      } else {
        $p->kill(9);
      }
    }
  }

  if ($match) {
    push @errors, "Found $match matching expected PID (already running).";
    return output("not started", @errors);
  }

  $this->do_log( 'Initializing Daemon', 'daemon' );

# first install some critical signal handler so that main script wont get killed
  $SIG{ALRM} = sub {
    $this->do_log( "Got alarm signal.. nothing to do", 'daemon' );
  };
  $SIG{PIPE} = sub {
    $this->do_log( "Got PIPE signal.. nothing to do", 'daemon' );
  };

  if ( $this->{daemonize} ) {

    # first daemonize
    my $pid = fork;
    if ($pid) {
      # parent
      open my $fh, ">>", $this->{pidfile};
      print $fh $pid;
      close $fh;
      $this->do_log( 'Deamonized with PID ' . $pid, 'daemon' );
      $result = "started.";
      return output($result,@errors);
      exit();
    } elsif ($pid == -1) {
      # failed
      $result = "not started.";
      push @errors, "Couldn't fork: $!";
      return output($result,@errors);
    } else {
      # child
      open STDIN, '<', '/dev/null';
      open STDOUT, '>>', '/dev/null';
      open STDERR, '>>', '/dev/null';
      setsid();
      umask 0;
    }
  } else {
    my $pid = $$;
    open my $fh, ">>", $this->{pidfile};
    print $fh $pid;
    close $fh;
  }

  $this->pre_fork_hook();
  $this->fork_children();
  return;
}

sub exit_daemon ($this) {
  my $result = 'not stopped';
  my $time_before_hardkill = $this->{time_before_hardkill};

  my @errors;
  my @pids = $this->read_pid_file();

  require Proc::ProcessTable;
  my $t = new Proc::ProcessTable;

  my @running = ();
  my $match = 0;
  foreach my $p ( @{ $t->table } ) {
    my $cmndline = $p->{'cmndline'};
    $cmndline =~ s/\s*$//g;
    if ($cmndline eq $this->{'name'}) {
      if ($p->{'pid'} == $$) {
        next;
      }
      push @running, $p->{'pid'};
      if (grep { /$p->{'pid'}/ } @pids) {
        push @errors, "Active process detected ($p->{'pid'}). Killing... ";
        $match = $p->{'pid'};
      } else {
        push @errors, "Orphaned process detected ($p->{'pid'}). Killing... ";
      }

      my $pidstillhere = 1;
      my $start_ps = [gettimeofday];
      while ($pidstillhere) {
          if ( tv_interval($start_ps) > $time_before_hardkill ) {
            $p->kill(9);
            last;
          } else {
            $p->kill(15);
          }
          sleep 1;
          $pidstillhere = 0;
          my $n = new Proc::ProcessTable;
          foreach ( @{$t->table} ) {
          if ($_->{'pid'} == $p->{'pid'}) {
            $pidstillhere = 1;
            last;
          }
        }
      }
      if ($pidstillhere) {
        $errors[scalar(@errors)-1] .= "Failed.";
      } else {
        pop @running;
        $errors[scalar(@errors)-1] .= "Done.";
      }
    }
  }

  if (scalar @running) {
      push @errors, "Failed to stop all processes (" . join(', ',@running) . ") not stopped.";
  } elsif ($match) {
      $result = "stopped.";
      @errors = ();
  } else {
      push @errors, "No existing active process found.";
  }

  return output($result,@errors);
}

sub status ($this) {
  $this->status_hook();
  return;
}

sub get_daemon_counts ($this) {
  return $daemoncounts_;
}

sub read_pid_file ($this) {
  my @pids;
  if ( open(my $PIDFILE, '<', $this->{pidfile} ) ) {
    while (<PIDFILE>) {
      push @pids, $1 if (/(\d+)/);
    }
  }
  return @pids;
}

sub fork_children ($this) {
  $SIG{'TERM'} = sub {
    $this->do_log(
      'Main thread got a TERM signal. Proceeding to shutdown...',
      'daemon'
    );

    foreach my $t ( threads->list(threads::running) ) {
      if ( $this->{clean_thread_exit} ) {
        $this->do_log( "Sending TERM signal to thread " . $t->tid, 'daemon' );
        # does not always work, TERM signal cannot interrupt accept() call in thread
        $t->kill('TERM');
      } else {
        $t->detach();
      }
    }

    $this->post_kill_hook();

    while ( threads->list() > 0 ) {
      my $thread_count = threads->list();
      $this->do_log( "Still $thread_count threads running...", 'daemon' );
      sleep 1;
    }

    while ( threads->list(threads::running) > 0 ) {
      my $thread_count = threads->list(threads::running);
      $this->do_log( "Still $thread_count threads running...", 'daemon' );
      sleep 1;
    }
    $this->do_log( "All threads finished!", 'daemon' );
    foreach my $t ( threads->list(threads::joinable) ) {
      $this->do_log( "Joining thread " . $t->tid, 'daemon' );
      my $res = $t->join();
    }

    ## let our child class a chance do clean up stuff
    $this->exit_hook();
    $this->do_log( "All threads finished and joined. ", 'daemon' );
    $this->do_log( 'Bye !',                             'daemon' );
    $this->close_log();
    exit();
  };

  my $leaving = 0;
  while (1) {
    last if ($leaving);
    my $thread_count = threads->list(threads::running);
    for ( $thread_count .. $this->{prefork} - 1 ) {
      $this->make_new_child();
      sleep $this->{interval};
    }

    $this->do_log(
      "Population check done ("
      . $thread_count
      . "), waiting "
      . $this->{'allthreadsrestartin'}
      . " seconds for next check..",
      'daemon', 'debug'
    );

    sleep $this->{'allthreadsrestartin'};
  }
  $this->do_log( "Error, in main thread neverland !", 'daemon', 'error' );
  return;
}

sub make_new_child ($this) {
  my $pid;
  my $sigset;

  my $threadnumber = $this->get_nb_threads() + 1;
  $this->do_log(
    "Lauching new thread ($threadnumber/" . $this->{prefork} . ") ...",
    'daemon' );
  ## main_loop_hook
  my $t = threads->create( { 'void' => 1 }, sub { $this->main_loop_hook(); } );
  return;
}

#### Available Hooks
sub main_loop_hook ($this) {
  while (1) {
    $this->do_log( 'In dummy main loop...', 'daemon' );
    sleep 5;
  }
  return;
}

sub pre_fork_hook ($this) {
  $this->do_log( 'No pre_fork_hook redefined, using default one...', 'daemon' );
  return 1;
}

sub exit_hook ($this) {
  $this->do_log( 'No exit_hook redefined, using default one...', 'daemon' );
  return 1;
}

sub post_kill_hook ($this) {
  $this->do_log( 'No post_kill_hook redefined, using default one...', 'daemon' );
  return 1;
}

sub status_hook ($this) {
  my @errors;

  my @pids = $this->read_pid_file();
  my $time_before_hardkill = $this->{time_before_hardkill};

  require Proc::ProcessTable;
  my $t = new Proc::ProcessTable;
  my @match;
  foreach my $p ( @{ $t->table } ) {
    my $cmndline = $p->{'cmndline'};
    $cmndline =~ s/\s*$//g;
    if ($cmndline eq $this->{'name'}) {
      if ($p->{'pid'} == $$) {
        next;
      } elsif (grep { /$p->{'pid'}/ } @pids) {
        push @match, $p->{'pid'};
      } else {
        push @errors, "Orphaned process detected ($p->{'pid'})";
      }
    }
  }

  if (scalar(@pids)) {
    if (scalar(@match) == scalar(@pids)) {
      if (scalar(@errors)) {
        return "running with errors.\n  " . join('\n  ',@errors);
      } else {
        return "running.";
      }
    } else {
      my @missing;
      foreach (@pids) {
        unless (grep { /$_/ } @{ $t->table }) {
          push @missing, $_;
        }
      }
      if (scalar @missing) {
        push @errors, "Expected PIDs from PID file not found: " . join(', ',@missing);
      }
    }
  }

  if (scalar(@errors)) {
    return "not running, but errors found.\n  " . join('\n  ',@errors);
  }
  return "not running.";
}

#### Threads tools
sub get_nb_threads ($this) {
  my @tlist = threads->list;
  if (@tlist) {
    $this->{nbthreads} = @tlist;
    return $this->{nbthreads};
  }
  return 0;
}

sub get_thread_id ($this) {
  my $t = threads->self;
  return $t->tid;
}

##### Log management
sub do_log ($this, $message, $given_set, $priority = 'info') {
  foreach my $set ( @{ $this->{logged_sets} } ) {
    if ( $set eq 'all' || !defined($given_set) || $set eq $given_set ) {
      if ( $log_prio_levels{$priority} <= $this->{log_prio_level} ) {
        $this->do_effective_log($message);
      }
      last;
    }
  }
  return;
}

sub do_effective_log ($this, $message) {
  foreach my $line ( split( /\n/, $message ) ) {
    $this->write_log_to_file($line) if ( $this->{logfile} ne '' );
    if ( $this->{'syslog_facility'} ne '' && $this->{'syslog_progname'} ne '' ) {
      syslog( 'info', '(' . $this->get_thread_id() . ') ' . $line );
    }
  }
  return;
}

sub write_log_to_file ($this, $message) {
  chomp($message);
  return if ( $this->{logfile} eq '' );

  my $LOCK_SH = 1;
  my $LOCK_EX = 2;
  my $LOCK_NB = 4;
  my $LOCK_UN = 8;
  $| = 1;

  if ( !defined( fileno($LOGGERLOG) ) || !-f $this->{logfile} ) {
    open($LOGGERLOG, ">>", $this->{logfile});
    if ( !defined( fileno($LOGGERLOG) ) ) {
      open $LOGGERLOG, ">>", "/tmp/".$this->{logfile};
      $| = 1;
    }
    $this->do_log( 'Log file has been opened, hello !', 'daemon' );
  }
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
  $mon++;
  $year += 1900;
  my $date = sprintf( "%d-%.2d-%.2d %.2d:%.2d:%.2d",
    $year, $mon, $mday, $hour, $min, $sec );
  flock( $LOGGERLOG, $LOCK_EX );
  print $LOGGERLOG "$date (" . $this->get_thread_id() . ") " . $message . "\n";
  flock( $LOGGERLOG, $LOCK_UN );
  return;
}

sub close_log ($this) {
  $this->do_log( 'Closing log file now.', 'daemon' );
  close $LOGGERLOG;
  exit;
}

sub format_time ($this, $time) {
  my $res     = '';
  my $hours   = int( $time / ( 60 * 60 ) );
  my $rest    = $time % ( 60 * 60 );
  my $minutes = int( $rest / 60 );
  my $seconds = $rest % 60;

  $res = $hours . "h " . $minutes . "m " . $seconds . "s";
  return $res;
}

##### profiling
sub profile_start ($this) {
  return unless $PROFILE;
  my $var = shift;
  $prof_start{$var} = [gettimeofday];
  return;
}

sub profile_stop ($this) {
  return unless $PROFILE;
  my $var = shift;
  return unless defined( $prof_start{$var} );
  my $interval = tv_interval( $prof_start{$var} );
  my $time     = ( int( $interval * 10000 ) / 10000 );
  $prof_res{$var} = $time;
  return $time;
}

sub profile_output ($this) {
  return unless $PROFILE;
  my $out = "";
  foreach my $var ( keys %prof_res ) {
    $out .= " ($var:" . $prof_res{$var} . "s)";
  }
  $this->do_log($out);
  return;
}

sub output ($result, @errors) {
  if (scalar @errors) {
    print STDOUT "$result\n  " . join("\n  ",@errors) . "\n";
    return 1;
  }
  print STDOUT $result . "\n";
  return 0;
}

1;
