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

package UDPDaemon;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use POSIX qw( SIGINT SIG_BLOCK SIG_UNBLOCK );
use Sys::Hostname();
use Socket();
use Symbol();
use IO::Socket::INET();
use Mail::SpamAssassin::Timeout();

our $LOGGERLOG;

sub new ($class, $daemonname, $conffilepath) {
  my $conf = ReadConfig::get_instance();
  my $configfile = $conf->get_option('SRCDIR')."/".$conffilepath;

  ## default values
  my $pidfile = $conf->get_option('VARDIR')."/run/$daemonname.pid";
  my $port = 10000;
  my $logfile = $conf->get_option('VARDIR')."/log/spamtagger/$daemonname.log";
  my $daemontimeout = 86400;
  my $clienttimeout = 5;
  my $sockettimeout = 120;
  my $listenmax = 100;
  my $prefork = 1;
  my $debug = 1;
  my %childrens;

  my $this = {
    name => $daemonname,
    port => $port,
    server => '',
    pidfile => $pidfile,
    logfile => $logfile,
    daemontimeout => $daemontimeout,
    clienttimeout => $clienttimeout,
    sockettimeout => $sockettimeout,
    listenmax => $listenmax,
    debug => $debug,
    prefork => $prefork,
    children => 0,
    basefork => 0,
    inexit => 0,
    childrens => (),
    time_to_die => 0,
  };

  # replace with configuration file values
  my $CONFFILE;
  if (open($CONFFILE, '<', $configfile)) {
    while (<$CONFFILE>) {
      chomp($_);
      next if $_ =~ /^\#/;
      if ($_ =~ /^(\S+)\ ?\=\ ?(.*)$/) {
        $this->{$1} = $2 if (defined($this->{$1}));
      }
    }
    close $CONFFILE;
  }

  bless $this, $class;
  return $this;
}

sub log_message ($this, $message) {
  if ($this->{debug}) {
    unless (defined(fileno($LOGGERLOG))) {
      open($LOGGERLOG, ">>", "/tmp/$this->{logfile}");
      $| = 1; ## no critic
    }
    my $date=`date "+%Y-%m-%d %H:%M:%S"`;
    chomp($date);
    print $LOGGERLOG "$date: $message\n";
  }
  return;
}

######
## startDaemon
######
sub start_daemon ($this) {
  open $LOGGERLOG, ">>", $this->{logfile};

  my $pid = fork();
  die "Couldn't fork: $!" unless (defined($pid));
  if ($pid) {
    exit;
  } else {
    # Dameonize
    POSIX::setsid();

    $this->log_message("Starting Daemon");

    $SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{ALRM} = sub { $this->parent_got_signal(); }; ## no critic

    #alarm $this->{daemontimeout};
    $0 = $this->{'name'}; ## no critic
    $this->init_daemon();
    $this->launch_childs();
    until ($this->{time_to_die}) {};
  }
  exit;
}

sub parent_got_signal ($this) {
  $this->{time_to_die} = 1;
  return;
}


sub reaper ($this) {
  $this->log_message("Got child death...");
  $SIG{CHLD} = sub { $this->reaper(); }; ## no critic
  my $pid = wait;
  $this->{children}--;
  delete $this->{childrens}{$pid};
  if ($this->{time_to_die} < 1 ) {
    $this->log_message("Not yet dead.. relauching new child");
    $this->make_child();
  }
  return;
}

sub huntsman ($this) {
  local($SIG{CHLD}) = 'IGNORE'; ## no critic
  $this->{time_to_die} = 1;
  $this->log_message("Shutting down childs");
  kill 'INT' => keys %{$this->{childrens}};
  $this->log_message("Daemon shut down");
  exit;
}

sub init_daemon ($this) {
  $this->log_message("Initializing Daemon");
  $this->{server} = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $this->{port},
    Proto     => 'udp'
  ) or die "Couldn't be an udp server on port ".$this->{port}." : $@\n";

  $this->log_message("Listening on port ".$this->{port});
  return 0;
}

sub launch_childs ($this) {
  for (1 .. $this->{prefork}) {
    $this->log_message("Launching child ".$this->{children}." on ".$this->{prefork}."...");
    $this->make_child();
  }
  # Install signal handlers
  $SIG{CHLD} = sub { $this->reaper(); }; ## no critic
  $SIG{INT} = sub { $this->huntsman(); }; ## no critic

  while (1) {
    sleep;
    $this->log_message("Child death... still: ".$this->{children});
    for (my $i = $this->{children}; $i < $this->{prefork}; $i++) {
      $this->make_child();
    }
  }
  return;
}

sub make_child ($this) {
  my $pid;
  my $sigset;

  if ($this->{time_to_die} > 0) {
    $this->log_message("Not creating child because shutdown requested");
    exit;
  }
  # block signal for fork
  $sigset = POSIX::SigSet->new(SIGINT);
  sigprocmask(SIG_BLOCK, $sigset) or die "Can't block SIGINT for fork: $!\n";

  die "fork: $!" unless defined ($pid = fork);

  if ($pid) {
    # Parent records the child's birth and returns.
    sigprocmask(SIG_UNBLOCK, $sigset) or die "Can't unblock SIGINT for fork: $!\n";
    $this->{childrens}{$pid} = 1;
    $this->{children}++;
    $this->log_message("Child created with pid: $pid");
    return;
  }
  # Child can *not* return from this subroutine.
  $SIG{INT} = sub { }; ## no critic

  # unblock signals
  sigprocmask(SIG_UNBLOCK, $sigset) or die "Can't unblock SIGINT for fork: $!\n";

  $this->log_message("In child listening...");
  $this->listen_for_query();
  exit;
}

sub listen_for_query ($this) {
  my $message;
  my $serv = $this->{server};
  my $MAXLEN = 1024;

  $this->{'lastdump'} = time();
  my $data;
  while (my $cli = $serv->recv($data, $MAXLEN)) {
    my($cli_add, $cli_port) =  sockaddr_in($serv->peername);
    $this->manage_client($cli, $cli_port, $data);
    my $time = int(time());
  }
  return;
}

sub manage_client ($this, $cli, $cli_add, $data) {
  alarm $this->{daemontimeout};

  if ($data =~ /^EXIT/) {
    $this->log_message("Received EXIT command");
    $this->huntsman();
    exit;
  }
  my $query = $data;
  chomp($query);
  if ($query =~ /^HELO\ (\S+)/) {
    $this->{server}->send("NICE TO MEET YOU: $1\n");
  } elsif ($query =~ /^NULL/) {
    $this->{server}->send("\n");
  } else {
    my $result = $this->process_datas($data);
    $this->{server}->send("$result\n");
  }
  return;
}

###########################
## client call
sub exec_call ($this, $command) {
  my $res = "NORESPONSE";
  my $t = Mail::SpamAssassin::Timeout->new({ secs => $this->{clienttimeout} });
  $t->run( sub { $res = $this->query_daemon($command);  });

  if ($t->timed_out()) { return "TIMEDOUT"; };

  return $res;
}

sub query_daemon ($this, $query) {
  my $socket;
  if ($socket = IO::Socket::INET->new(
      PeerAddr => '127.0.0.1',
      PeerPort => $this->{port},
      Proto    => "udp"
    )) 
  {
    $socket->send($query."\n");
    my $MAXLEN  = 1024;
    my $response;

    local $! = 0;

    $socket->recv($response, $MAXLEN);
    return "NODAEMON" unless ($! != /^$/);

    my $res = $response;
    chomp($res);
    return $res;
  }
  return "NODAEMON";
}

sub timed_out ($this) {
  exit();
}

1;
