#!/usr/bin/env perl

package PreForkDaemon;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use POSIX qw( SIGINT SIG_BLOCK SIG_UNBLOCK );
use Sys::Hostname();
use Socket();
use Symbol();
use IPC::Shareable();
use Data::Dumper();
use Mail::SpamAssassin::Timeout();
use ReadConfig();
use Time::HiRes qw(gettimeofday tv_interval);
our $LOGGERLOG;

my $PROFILE = 1;
my (%prof_start, %prof_res) = ();

sub new ($class, $daemonname, $conffilepath, $spec_this) {
  my $conf = ReadConfig::get_instance();
  my $configfile = $conf->get_option('SRCDIR')."/".$conffilepath;

  ## default values
  my $pidfile = $conf->get_option('VARDIR')."/run/$daemonname.pid";
  my $port = 10000;
  my $logfile = $conf->get_option('VARDIR')."/log/spamtagger/$daemonname.log";
  my $daemontimeout = 86400;
  my $prefork = 5;
  my $debug = 0;

  my $this = {
         name => $daemonname,
         server => '',
         pidfile => $pidfile,
         logfile => $logfile,
         daemontimeout => $daemontimeout,
         debug => $debug,
         prefork => $prefork,
         basefork => 0,
         inexit => 0,
         needshared => 0,
         clearshared => 0,
         glue => 'ABCD',
         gluevalue => '0x44434241',
         sharedcreated => 0,
         finishedforked => 0,
         interval => 10
     };
  $this->{shared} = {};

  # add specific options of child object
  $this->{$_} = $spec_this->{$_} foreach (keys(%{$spec_this}));

  # replace with configuration file values
  my $CONFFILE;
  if (open($CONFFILE, '<', $configfile)) {
    while (<$CONFFILE>) {
      chop;
      next if /^\#/;
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $this->{$1} = $2;
      }
    }
    close $CONFFILE;
  }

  # Set process name
  $0 = $this->{name}; ## no critic
  return bless $this, $class;
}

sub create_shared ($this) {
  if ($this->{needshared}) {

    ## first, clear shared
    $this->clear_system_shared();

    my %options = (
      create    => 'yes',
      exclusive => 0,
      mode      => 0644, ## no critic (leading zero octal notation)
      destroy   => 0
    );

    my $glue = $this->{glue};
    my %sharedhash;
    # set shared memory
    tie %sharedhash, 'IPC::Shareable', $glue, { %options } or die "server: tie failed\n";
    $this->{shared} = \%sharedhash;
    $this->init_shared(\%sharedhash);
    $this->{sharedcreated} = 1;
  }
  return 1;
}

# global variables
my %children = ();       # keys are current child process IDs
my $children = 0;        # current number of children
my %shared;

sub reaper ($this) {
  $SIG{CHLD} = \&reaper; ## no critic
  my $pid = wait;
  $children --;
  delete $children{$pid};
  return;
}

sub huntsman ($this) {
  local($SIG{CHLD}) = 'IGNORE';

  until ($this->{finishedforked}) {
    $this->log_message('Not yet finished forking...');
    sleep 2;
  }

  for my $pid (keys %children) {
    kill 'INT', $pid;
    $this->log_message("Child $pid shut down");
  }

  if ($this->{clearshared} > 0) {
    IPC::Shareable->clean_up_all;
  }
  $this->log_message('Daemon shut down');
  exit_clean();
  return;
}

sub log_message ($this, $message) {
  $this->do_log($message);
  return;
}

sub log_debug ($this, $message) {
  $this->do_log($message) if ($this->{debug});
  return;
}

sub do_log ($this, $message) {
  unless (defined(fileno($LOGGERLOG))) {
    open($LOGGERLOG, ">>", $this->{logfile});
    $| = 1; ## no critic
  }
  unless (defined(fileno($LOGGERLOG))) {
    open $LOGGERLOG, ">>", "/tmp/".$this->{logfile};
    $| = 1; ## no critic
  }
  my $date=`date "+%Y-%m-%d %H:%M:%S"`;
  chop($date);
  print $LOGGERLOG "$date (".$$."): $message\n";
  close $LOGGERLOG;
  return;
}

sub init_daemon ($this) {
  $this->log_message('Initializing Daemon');
  # first daemonize
  my $pid = fork;
  if ($pid) {
    my $cmd = "echo $pid > ".$this->{pidfile};
    `$cmd`;
  }
  exit() if $pid;
  die "Couldn't fork: $!" unless defined($pid);
  $this->log_message('Deamonized');

  ## preForkHook
  $this->pre_fork_hook();

  # and then fork children
  $this->fork_children();

  return 0;
}

sub fork_children ($this) {
  # Fork off our children.
  for (1 .. $this->{prefork}) {
    $this->make_new_child();
    sleep $this->{interval};
  }

  # Install signal handlers.
  $SIG{CHLD} = sub { $this->reaper(); }; ## no critic
  $SIG{INT}  = $SIG{TERM} = sub { $this->huntsman(); }; ## no critic

  $this->{finishedforked} = 1;
  # And maintain the population.
  while (1) {
    sleep;  # wait for a signal (i.e., child's death)
    for (my $i = $children; $i < $this->{prefork}; $i++) {
      $this->make_new_child(); # top up the child pool
    }
  }
  return;
}

sub make_new_child ($this, $pid, $sigset) {
  # block signal for fork
  $sigset = POSIX::SigSet->new(SIGINT);
  sigprocmask(SIG_BLOCK, $sigset)
    or die "Can't block SIGINT for fork: $!\n";

  die "fork: $!" unless defined ($pid = fork);

  if ($pid) {
    # Parent records the child's birth and returns.
    sigprocmask(SIG_UNBLOCK, $sigset)
      or die "Can't unblock SIGINT for fork: $!\n";
    $children{$pid} = 1;
    $children++;
    return;
  } else {
    # Child can *not* return from this subroutine.
    # make SIGINT kill us as it did before
    $SIG{INT} = 'DEFAULT'; ## no critic

    # unblock signals
    sigprocmask(SIG_UNBLOCK, $sigset)
      or die "Can't unblock SIGINT for fork: $!\n";

    # get shared memory
    if ($this->{needshared} && $this->{sharedcreated}) {
      my %options = (
        create    => 0,
        exclusive => 0,
        mode      => 0644, ## no critic (leading zero octal notation)
        destroy   => 0,
      );
      my $glue = $this->{glue};
      # set shared memory
      tie %shared, 'IPC::Shareable', $glue, { %options }; # or die "server: tie failed\n";
      $this->{shared} = \%shared;
    }

    ##
    $SIG{ALRM} = sub { $this->exit_child(); }; ## no critic
    alarm 10;
    ## mainLoopHook
    $this->main_loop_hook();

    # tidy up gracefully and finish

    # this exit is VERY important, otherwise the child will become
    # a producer of more and more children, forking yourself into
    # process death.
    exit();
  }
  return;
}

sub clear_system_shared ($this) {
  my $cmd = "ipcrm -M ".$this->{gluevalue};
  `$cmd 2>&1 > /dev/null`;
  $cmd = "ipcrm -S ".$this->{gluevalue};
  `$cmd 2>&1 > /dev/null`;

  sleep 2;
  return;
}

sub pre_fork_hook ($this) {
  $this->log_message('No preForkHook redefined, using default one...');
  return 1;
}

sub main_loop_hook ($this) {
  while(1) {
    sleep 5;
    $this->log_message('No mainLoopHook redefined, waiting in default loop...');
  }
  return 1;
}

sub exit_clean ($this) {
  $this->log_message('Exit called');
  $this->log_message('...');

  my $ppid = `cat $this->{pidfile}`;
  kill 'INT', $ppid;
  return 1;
}

sub exit_child ($this) {
  return 1;
}
############################################

sub profile_start ($var) {
  return unless $PROFILE;
  $prof_start{$var} = [gettimeofday];
  return;
}

sub profile_stop ($var) {
  return unless $PROFILE;
  return unless defined($prof_start{$var});
  my $interval = tv_interval ($prof_start{$var});
  my $time = (int($interval*10000)/10000);
  $prof_res{$var} = $time;
  return $time;
}

sub profile_output {
  return unless $PROFILE;
  my $out = "";
  $out .= " ($_:".$prof_res{$_}."s)" foreach (keys(%prof_res));
  print $out;
  return;
}

1;
