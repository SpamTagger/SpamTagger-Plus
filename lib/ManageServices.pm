#!/usr/bin/env perl
package ManageServices;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

#no warnings 'uninitialized';
use lib '/usr/spamtagger/lib';
use lib '/usr/spamtagger/lib/ManageServices';
use threads ();
use threads::shared();
use Time::HiRes qw( gettimeofday tv_interval );
use POSIX();
use Sys::Syslog();
use ReadConfig();
use ConfigTemplate();
use Proc::ProcessTable();

our $init_dir = '/usr/spamtagger/etc/init.d';
our $restart_dir = '/var/spamtagger/run';
our $log_levels = { 'error' => 0, 'info' => 1, 'debug' => 2 };
our $LOGGERLOG;

our %default_configs = (
  'VARDIR'  => '/var/spamtagger',
  'SRCDIR'  => '/usr/spamtagger',
  'debug'    => 1,
  'uid'    => 0,
  'gid'    => 0,
  'timeout'  => 5,
);

our %default_actions = (
  #TODO
  'start'    => {
    'desc'    => 'start service or report if already running',
    'cmd'    => sub {
      my $this = shift;
      return $this->start();
    },
  },
  'stop'    => {
    'desc'    => 'stop serivce, if running',
    'cmd'    => sub {
      my $this = shift;
      return $this->stop();
    },
  },
  #TODO
  'restart'  => {
    'desc'    => 'stop serivce, if running, then start fresh',
    'cmd'    => sub {
      my $this = shift;
      return $this->restart();
    },
  },
  'status'  => {
    'desc'    => 'get current status',
    'cmd'    => sub {
      my $this = shift;
      return $this->status(0);
    },
  },
  'enable'  => {
    'desc'    => 'enable service and start automatically',
    'cmd'    => sub {
      my $this = shift;
      return $this->enable();
    },
  },
  'disable'  => {
    'desc'    => 'stop and prevent from starting until enabled',
    'cmd'    => sub {
      my $this = shift;
      return $this->disable();
    },
  },
  'pids'    => {
    'desc'    => 'get process id(s) for service',
    'cmd'    => sub {
      my $this = shift;
      if ($this->status(0) == 7) {
        return $this->clear_flags(7);
      }
      my @pids = $this->pids();
      if (scalar(@pids)) {
        return 'running with pid(s) ' . join(', ', @pids);
      } else {
        return 0;
      }
    },
  },
  'dump_config'  => {
    'desc'    => 'list module configuration',
    'cmd'    => sub {
      my $this = shift || die "Failed to load object";
      foreach my $key (keys(%{$this->{'module'}})) {
        print "$key = $this->{'module'}->{$key}\n";
      }
      return;
    },
  }
);

sub new ($class, %params) {
  my $conf = ReadConfig::get_instance();

  my $this = {
    'init_dir'   => $params{'init_dir'} || $init_dir,
    'restart_dir'   => $params{'restart_dir'} || $restart_dir,
    'process_table'   => Proc::ProcessTable->new(),
    'codes'    => get_codes(),
    'auto_start'  => $params{'auto_start'}  || 0,
    'conf'    => $conf,
    'timeout'  => 5,
  };
  $this->{'services'} = get_services($this->{'init_dir'});
  return bless $this, $class;
}

sub get_codes {
  my %codes = (
    -1  => {
      'verbose'  => 'unknown service',
      'suffix'  => undef,
    },
    0  => {
      'verbose'  => 'critical (not running and required)',
      'suffix'  => 'stopped',
    },
    1  => {
      'verbose'  => 'running',
      'suffix'  => undef,
    },
    2  => {
      'verbose'  => 'stopped (not running but not required)',
      'suffix'  => 'stopped',
    },
    3  => {
      'verbose'  => 'needs restart',
      'suffix'  => 'rn',
    },
    4  => {
      'verbose'  => 'currently stopping',
      'suffix'  => 'start.rs',
    },
    5  => {
      'verbose'  => 'currently starting',
      'suffix'  => 'stop.rs',
    },
    6  => {
      'verbose'  => 'currently restarting (currently processing stop/start script)',
      'suffix'  => 'restart.rs',
    },
    7  => {
      'verbose'  => 'disabled',
      'suffix'  => 'disabled',
    },
  );
  return \%codes;
}

sub get_services ($init = $init_dir) {
  my %services = (
    #'apache'   => {
      #'name'    => 'Web access',
      #'module'  => 'Apache',
      #'critical'  => 1,
    #},
    'clamd'    => {
      'name'    => 'ClamAV daemon',
      'module'  => 'ClamD',
      'critical'  => 1,
    },
    'clamspamd'  => {
      'name'    => 'ClamSpam daemon',
      'module'  => 'ClamSpamD',
      'critical'  => 1,
    },
    #'cron'    => {
      #'name'    => 'Scheduler',
      #'module'  => 'Cron',
      #'critical'  => 1,
    #},
    #'dccifd'   => {
      #'name'    => 'DCC client daemon',
      #'module'  => 'Apache',
      #'critical'  => 1,
    #},
    #'exim_stage1'   => {
      #'name'    => 'Incoming MTA',
      #'module'  => 'Exim',
      #'critical'  => 1,
    #},
    #'exim_stage2'   => {
      #'name'    => 'Filtering MTA',
      #'module'  => 'Exim',
      #'critical'  => 1,
    #},
    #'exim_stage4'   => {
      #'name'    => 'Outgoing MTA',
      #'module'  => 'Exim',
      #'critical'  => 1,
    #},
    #'fail2ban'  => {
      #'name'    => 'Fail2Ban',
      #'module'  => 'Fail2Ban',
      #'critical'  => 1,
    #},
    #'greylistd'  => {
      #'name'    => 'Greylist daemon',
      #'module'  => 'GreylistD',
      #'critical'  => 1,
    #},
    #'mailscanner'  => {
      #'name'    => 'Filtering engine',
      #'module'  => 'MailScanner',
      #'critical'  => 1,
    #},
    #'mariadb_master'  => {
      #'name'    => 'Master database',
      #'module'  => 'MySQL',
      #'critical'  => 1,
    #},
    #'mariadb_slave'  => {
      #'name'    => 'Slave database',
      #'module'  => 'MySQL',
      #'critical'  => 1,
    #},
    'newsld'  => {
      'name'    => 'Newsletters daemon',
      'module'  => 'NewslD',
      'critical'  => 1,
    },
    'ntpd'    => {
      'name'    => 'NTPD',
      'module'  => 'NTPD',
      'critical'  => 1,
    },
    #'preftdaemon'  => {
      #'name'    => 'Preferences daemon',
      #'module'  => 'PrefTDaemon',
      #'critical'  => 1,
    #},
    #'snmpd'    => {
      #'name'    => 'SNMP daemon',
      #'module'  => 'SNMPD',
      #'critical'  => 1,
    #},
    'spamd'   => {
      'name'    => 'SpamAssassin daemon',
      'module'  => 'SpamD',
      'critical'  => 1,
    },
    #'spamhandler'  => {
      #'name'    => 'Filtering engine',
      #'module'  => 'SpamHandler',
      #'critical'  => 1,
    #},
  );
  return \%services;
}

sub load_module ($this, $service) {
  if ( defined($this->{'module'}->{'syslog_facility'}) &&
    $this->{'module'}->{'syslog_facility'} ne '' )
  {
    closelog( $this->{'service'},
      'ndelay,pid,nofatal', $this->{'module'}->{'syslog_facility'} );
  }

  $this->{'config'} = \%default_configs;

  $this->{'service'} = $service;

  my $module = $this->{'services'}->{$this->{'service'}}->{'module'} ||
    die "$this->{'service'} has no declared 'module'\n";

  require "ManageServices/" . $module . ".pm";
  $module = "ManageServices::".$module;
  $this->{'module'} = init($module, $this);
  $this->get_config() || return 0;
  $this->get_actions() || return 0;

  foreach my $file (('pidfile', 'logfile', 'socketpath')) {
    if (defined($this->{'module'}->{$file}) && -f $this->{'module'}->{$file}) {
      chown(
        $this->{'module'}->{'uid'},
        $this->{'module'}->{'gid'},
        $this->{'module'}->{$file}
      );
    }
  }

  if ( defined($this->{'module'}->{'syslog_facility'}) &&
    $this->{'module'}->{'syslog_facility'} ne '' )
  {
    openlog( $this->{'service'},
      'ndelay,pid,nofatal', $this->{'module'}->{'syslog_facility'} );
  }

  $this->{'module'}->{'state'} = $this->status();
  unless (defined($this->{'module'}->{'state'})) {
    $this->{'module'}->{'state'} = 0;
  }

  return $this;
}

sub get_config ($this) {
  unless (defined $this->{'module'}) {
    die "must first load_module('service')";
  }

  foreach (keys %default_configs) {
    unless (defined($this->{'module'}->{$_})) {
      $this->{'module'}->{$_} = $default_configs{$_};
    }
  }

  my $conffile = $this->{'module'}->{'conffile'};
  if ( -f "${conffile}_template" ) {
    my $template = ConfigTemplate->new( $conffile."_template", $conffile );
    my $ret = $template->dumpFile();
  }
  my $CONFFILE;
  if ( open($CONFFILE, '<', $this->{'module'}->{'conffile'} )) {
    while (<$CONFFILE>) {
      chomp;
      next if /^\#/;
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $this->{'module'}->{$1} = $2;
      }
    }
    close $CONFFILE;
  }

  $this->{'module'}->{'uid'} = $this->{'module'}->{'user'} ? getpwnam( $this->{'module'}->{'user'} ) : 0;
  $this->{'module'}->{'gid'} = $this->{'module'}->{'group'} ? getgrnam( $this->{'module'}->{'group'} ) : 0;

  foreach my $key (keys %{$this->{'module'}}) {
    if (!defined($this->{'module'}->{$key})) {
      next;
    } elsif ($this->{'module'}->{$key} =~ m#^(false|no)$#i) {
      $this->{'module'}->{$key} = 0;
    } elsif ($this->{'module'}->{$key} =~ m#^(true|yes)$#i) {
      $this->{'module'}->{$key} = 1;
    }
  }

  return 1;
}

sub get_actions ($this) {
  my %actions = %default_actions;
  my $mod_actions = $this->{'module'}->{'actions'};
  foreach my $action (keys %{$mod_actions}) {
    foreach my $attr (keys %{$mod_actions->{$action}}) {
      $actions{$action}->{$attr} = $mod_actions->{$action}->{$attr};
    }
  }

  $this->{'module'}->{'actions'} = \%actions;
  return;
}

sub find_process ($this) {
  foreach my $p ( @{ $this->{'process_table'}->table() } ) {
    next if ($p->{'pid'} == $$);
    if ($p->{'cmndline'} =~ m#$this->{'module'}->{'cmndline'}#) {
      next if ($p->{'state'} eq 'defunct');
      return $p->{'pid'};
    }
  }
  return 0;
}

sub pids ($this, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  unless ($this->find_process()) {
    $this->clear_flags(0);
    return ();
  }

  my @pids;
  foreach my $p ( @{ $this->{'process_table'}->table() } ) {
    next if ($p->{'pid'} == $$);
    if ($p->{'cmndline'} =~ m#$this->{'module'}->{'cmndline'}#) {
      next if ($p->{'state'} eq 'defunct');
      push(@pids,$p->{'pid'});
    }
  }

  my @file_pids = $this->read_pid_file();
  if (scalar(@pids) != scalar(@file_pids)) {
    $this->write_pid_file(@pids);
  } else {
    foreach my $pid (@pids) {
      unless (grep { /^$pid$/ } @file_pids) {
        print STDERR "PIDs in process table do not match pidfile, updating\n";
        $this->write_pid_file(@pids);
        last;
      }
    }
  }

  return @pids;
}

sub create_module ($this, $defs) {
  my $file = $defs->{'conffile'} || $this->{'conf'}->get_option('SRCDIR').'/etc/spamtagger/'.$this->{'service'}.".cf";
  my $module = {};
  foreach my $key (keys %default_configs) {
    $module->{$key} = $default_configs{$key}
  }
  foreach my $key (keys %$defs) {
    $module->{$key} = $defs->{$key}
  }
  bless $module, 'ManageServices';

  my $tfile = $file . "_template";
  if ( -f $tfile ) {
    my $template = ConfigTemplate->new( $tfile, $file );
    my $ret = $template->dumpFile();
  }

  my $CONFFILE;
  if (open($CONFFILE, '<', $file)) {
    while (<$CONFFILE>) {
      chomp;
      next if /^\#/;
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $module->{$1} = $2;
      }
    }
    close $CONFFILE;
  }
  return $module;
}

sub status ($this, $auto_start = $this->{'auto_start'}, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  my $status = 0;
  my $running = $this->find_process();
  if (defined($this->{'services'}->{$this->{'service'}})) {
    if ( -e $this->{'restart_dir'}.'/'.$this->{'service'}.".disabled" ) {
      if ($running) {
        $running = $this->stop();
        if ( $running =~ /[02]/ ) {
          return $this->clear_flags(7);
        } else {
          return $this->clear_flags($running);
        }
      } else {
        return $this->clear_flags(7);
      }
    }
    for (my $i = 3; $i < 7; $i++) {
      if ( -e $this->{'restart_dir'}.'/'.$this->{'service'} . "." .
        $this->{'codes'}->{$i}->{'suffix'} )
      {
        if ( $i == 4 && !$running ) {
          $status = $this->clear_flags(0);
        } elsif ( $i == 5 && $running ) {
          $status = $this->clear_flags(1);
        } elsif ( $i > 3 &&
          ( stat($this->{'restart_dir'} .
          '/' . $this->{'service'} . "." .
          $this->{'codes'}->{$i}->{'suffix'}))[9]
          < (time() - 60) )
        {
          if ($auto_start) {
            return $this->clear_flags($this->restart());
          } else {
            return $this->clear_flags(3);
          }
        }
        last;
      }
    }
    if ($running) {
      return $this->clear_flags(1);
    } else {
      if ($auto_start) {
        return $this->clear_flags($this->start());
      } else {
        return $this->clear_flags(0);
      }
    }
  } else {
    return $this->clear_flags(-1);
  }
}

sub start ($this, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  return $this->clear_flags(7) if ($this->status(0) == 7);

  $this->do_log( "starting $this->{'service'}...", 'daemon' );

  if ($this->{'module'}->{'state'} =~ m/^[0235]$/) {
    $this->clear_flags(5);
  } else {
    return $this->{'module'}->{'state'};
  }

  if ($this->find_process()) {
    $this->do_log("$this->{'service'} already running.", 'daemon' );
    $this->clear_flags(1);
    return 1;
  }

  $this->setup();

  $this->do_log('Initializing Daemon', 'daemon');

  $SIG{ALRM} = sub { $this->do_log( "Got alarm signal.. nothing to do", 'daemon' ); }; ## no critic
  $SIG{PIPE} = sub { $this->do_log( "Got PIPE signal.. nothing to do", 'daemon' ); }; ## no critic

  if ($this->{'module'}->{'daemonize'}) {
    my $pid = fork;
    if ($pid) {
      $this->do_log( "Deamonized with PID $pid", 'daemon' );
      sleep(1);
      my @pids = $this->pids();
      my @remaining = ();
      foreach my $testing ( @pids ) {
        foreach ( @{ $this->{'process_table'}->table() } ) {
          if ($_->{'pid'} == $testing && $_->{'cmndline'} =~ m#$this->{'module'}->{'cmndline'}#i ) {
            if ($_->{'pid'} == $pid) {
              $this->do_log( 'Started successfully', 'daemon' );
            } else {
              $this->do_log( "Started child $_->{'pid'}", 'daemon' );
            }
            push @remaining, $_->{'pid'};
            last;
          }
        }
      }
      if (scalar(@remaining)) {
        $this->write_pid_file( @remaining );
        return $this->clear_flags(1);
      } else {
        $this->do_log( "Deamon doesn't exist after start. Failed.", 'daemon' );
        return 0;
      }
    } elsif ($pid == -1) {
      $this->do_log( 'Failed to fork', 'daemon' );
      $this->clear_flags(0);
      return $this->{'module'}->{'state'};
    } else {
  if ( $this->{'gid'} ) {
  }
      if ( $this->{'module'}->{'uid'} ) {
        die "Can't set UID $this->{'uid'}: $?\n" unless (setuid($this->{'uid'}));
      }
      $this->do_log("Set UID to $this->{'module'}->{'user'} ($<)", 'daemon');

      if ( $this->{'module'}->{'gid'} ) {
        die "Can't set GID $this->{'gid'}: $?\n" unless (setgrp($this->{'gid'}));
      }
      $this->do_log("Set GID to $this->{'module'}->{'group'} ($()", 'daemon');

      open STDIN, '<', '/dev/null';
      open STDOUT, '>>', '/dev/null';
      open STDERR, '>>', '/dev/null';
      setsid();
      umask 0;
    }
  } else {
    $this->write_pid_file( "$$" );
  }

  $this->pre_fork();
  if (defined($this->{'module'}->{'forks'}) && $this->{'module'}->{'forks'} > 0) {
    $this->fork_children();
  } else {
    my $ret = $this->main_loop();
    $this->clear_flags($ret);
    return $ret;
  }

  $this->clear_flags(0);
  return $this->{'module'}->{'state'};
}

sub stop ($this, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  my $running = $this->find_process();
  if ( $this->{'module'}->{'state'} =~ m/^[1356]$/ ) {
    $this->clear_flags(4);
  } elsif ( $this->{'module'}->{'state'} == 4 && $running == 0 ) {
    return $this->clear_flags(0);
  } else {
    return $this->{'module'}->{'state'};
  }

  $this->do_log( 'Stopping ' . $this->{'service'} . '...', 'daemon' );
  my $disabled = 0;
  if ( -e $this->{'restart_dir'}.'/'.$this->{'service'}.".disabled" ) {
    $this->do_log( $this->{'service'} . ' is disabled. Looking for remaining processes.', 'daemon' );
    $disabled = 1;
  }

  my @pids = $this->pids();
  my $pidstillhere = 1;
  my $start_ps = [gettimeofday];
  my $level = 15;
  while (scalar(@pids)) {
    if ( tv_interval($start_ps) > $this->{'module'}->{'timeout'} ) {
      $level = 9;
    }
    foreach my $p (@pids) {
      my $pid = fork();
      unless ($pid) {
        foreach ( @{ $this->{'process_table'}->table } ) {
          if ($_->{'pid'} == $p) {
            $_->kill($level);
            last;
          }
        }
        exit();
      }
    }
    sleep(1);
    if ($level == 9) {
      @pids = ();
    } else {
      @pids = $this->pids();
    }
  }

  if ($this->find_process()) {
    return $this->clear_flags(1);
  } else {
    $this->write_pid_file( () );
    if ($this->{'module'}->{'state'} == 6) {
      return $this->clear_flags(6)
    } elsif ($disabled) {
      return $this->clear_flags(7);
    } else {
      return $this->clear_flags(0);
    }
  }
}

sub restart ($this, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  if ( $this->{'module'}->{'state'} =~ m/^[0123]$/ ) {
    $this->clear_flags(6);
  } elsif ( $this->{'module'}->{'state'} =~ m/^[456]$/ ) {
    if ( -e $this->{'restart_dir'} . '/' . $this->{'service'} . "." .
      $this->{'codes'}->{$this->{'module'}->{'state'}}->{'suffix'} )
    {
      if ( (stat($this->{'restart_dir'} . '/' . $this->{'service'} . "." .
        $this->{'codes'}->{$this->{'module'}->{'state'}}->{'suffix'}
        ))[9] < (time() - 60) )
      {
        $this->clear_flags(3);
      } else {
        return $this->{'module'}->{'state'};
      }
    }
  } else {
    return $this->clear_flags(7);
  }

  if ($this->find_process($this->{'services'}->{$this->{'service'}}->{cmndline})) {
    if ($this->stop()) {
      return 3;
    } else {
      $this->clear_flags(5);
    }
  } else {
    $this->clear_flags(5);
  }
  return $this->start();
}

sub enable ($this, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  $this->clear_flags(1);
  return $this->restart();
}

sub disable ($this, $service = undef) {
  if (!defined($this->{'module'}) && defined($service)) {
    $this->load_module($service);
  }

  if ($this->stop() == 1) {
    return 1;
  } else {
    $this->clear_flags(7);
    return 7;
  }
}

sub check_all ($this) {
  my %results;
  foreach my $service (keys(%{$this->{'services'}})) {
    $this->{'service'} = $service;
    $this->load_module($service);
    $results{$service} = $this->status();
  }
  return \%results;
}

sub setup ($this) {
  $this->do_log( 'Setting up ' . $this->{'service'} . '...', 'daemon' );
  if ($this->{'module'}->setup($this)) {
    $this->do_log( 'Setup complete', 'daemon' );
  } else {
    $this->do_log( 'No Setup defined for ' . $this->{'service'} . '...', 'daemon' );
  }
  return;
}

sub pre_fork ($this) {
  $this->do_log( 'Running PreFork for ' . $this->{'service'} . '...', 'daemon' );
  if ($this->{'module'}->pre_fork($this)) {
    $this->do_log( 'PreFork complete', 'daemon' );
  } else {
    $this->do_log( 'No PreFork defined for ' . $this->{'service'} . '...', 'daemon' );
  }
  return;
}

sub main_loop ($this) {
  $this->do_log( 'Running MainLoop for ' . $this->{'service'} . '...', 'daemon' );
  if ($this->{'module'}->main_loop($this)) {
    $this->do_log( 'MainLoop complete', 'daemon' );
  } else {
    $this->do_log( 'In dummy main loop...', 'debug' );
    while (1) {
      sleep 5;
      $this->do_log( 'Continuing dummy main loop...', 'debug' );
    }
  }
  return 1;
}

sub fork_children ($this) {
  $SIG{'TERM'} = sub { ## no critic
    $this->do_log(
      'Main thread got a TERM signal. Proceeding to shutdown...',
      'daemon'
    );
    foreach my $t ( threads->list(threads::running) ) {
      $t->kill('TERM');
    }
    my $wait = 0;
    while ( threads->list() > 0 ) {
      $this->do_log( "Still " . treads->list() . " threads running...",
        'daemon' );
      $wait++;
      if ($wait == $this->{'module'}->{'timeout'}) {
        $this->do_log( "Taking too long. Detaching..." );
        foreach my $t ( threads->list() ) {
          $t->detach();
        }
      }
      sleep(1);
    }
    while ( threads->list(threads::running) > 0 ) {
      $this->do_log( "Still " . treads->list() . " threads running...",
        'daemon' );
      $wait++;
      if ($wait == $this->{'module'}->{'timeout'}) {
        $this->do_log( "Taking too long. Detaching..." );
        foreach my $t ( threads->list() ) {
          $t->detach();
        }
      }
      sleep(1);
    }
    foreach my $t ( threads->list(threads::joinable) ) {
      $this->do_log( "Joining thread " . $t->tid, 'daemon');
      my $res = $t->join();
    }

    $this->do_log( "Threads all stopped, cleaning...", 'daemon' );
    exit();
  };

  my $leaving = 0;
  while (!$leaving) {
    my $thread_count = threads->list(threads::running);
    for (my $ctr = 0; $ctr <= $this->{'module'}->{'forks'}; $ctr++) {
      $this->new_child();
      sleep($this->{'module'}->{'interval'});
    }

    $this->do_log(
      "Population check done (" . $thread_count .
      "), waiting " . $this->{'module'}->{'checktimer'} .
      " seconds for next check...", 'daemon', 'debug'
    );

    sleep($this->{'module'}->{'checktimer'});
  }
  $this->do_log("Error, in main thread neverland !", 'daemon', 'error' );
  return;
}

sub new_child ($this) {
  my $pid;

  my $thread_count = scalar(threads->list);
  if ($thread_count >= $this->{'module'}->{'children'}) {
    return 0;
  }
  $this->do_log(
    "Launching new thread (" . ($thread_count+=1) . "/" .
    $this->{'module'}->{'children'} . ") ...", 'daemon'
  );
  my $t = threads->create( { 'void' => 1 }, sub { $this->main_loop($this->{'module'}); } );
  return;
}

sub read_pid_file ($this) {
  my @pids;
  my $PIDFILE;
  return unless (open($PIDFILE, '<', $this->{'module'}->{'pidfile'}));
  while (<$PIDFILE>) {
    push(@pids, $_) if ($_ =~ m/^\d+$/);
  }
  return @pids;
}

sub write_pid_file ($this, @pids) {
  unless (scalar(@pids)) {
    unlink($this->{'module'}->{'pidfile'});
    return 1;
  }
  my $PIDFILE;
  if (open($PIDFILE, '>', $this->{'module'}->{'pidfile'} ) ) {
    foreach (@pids) {
      print $PIDFILE "$_\n";
    }
    close($PIDFILE);
    return 1;
  }
  print STDERR "Warning: $this->{'module'}->{'pidfile'} is not writable\n";
  return 0;
}

sub clear_flags ($this, $status) {
  if ($status == 0 && !$this->{'services'}->{$this->{'service'}}->{'critical'}) {
    $status = 2;
  }
  $this->{'module'}->{'state'} = $status;

  my $dh;
  opendir($dh, $this->{'restart_dir'});
  my @files = readdir($dh);
  closedir $dh;

  foreach my $code (keys(%{$this->{'codes'}})) {
    if (defined($this->{'codes'}->{$code}->{'suffix'})) {
      if ( -e $this->{'restart_dir'}.  '/' . $this->{'service'} .
        '.' . $this->{'codes'}->{$code}->{'suffix'} )
      {
        return $code if ($status =~ m/[456]/);
        unlink( $this->{'restart_dir'}. '/' . $this->{'service'} .
          '.' . $this->{'codes'}->{$code}->{'suffix'} );
      }
    }
  }

  if ( defined($this->{'codes'}->{$status}->{'suffix'}) ) {
    if ( $status < 3 ||
      $status > 6 ||
      ( !-e $this->{'restart_dir'} . '/' .
      $this->{'service'} . '.' .
      $this->{'codes'}->{$status}->{'suffix'} ) )
    {
      my $fh;
      open($fh, '>',
        $this->{'restart_dir'} . '/' .
        $this->{'service'} . '.' .
        $this->{'codes'}->{$status}->{'suffix'}
      );
      close($fh);
    }
  }
  return $status;
}

sub usage ($this) {
  if (defined($this->{'module'})) {
    print "Available actions:\n\n";
    my @actions;
    foreach my $action (keys %{$this->{'module'}->{'actions'}}) {
      if (defined($this->{'module'}->{'actions'}->{$action}->{'cmd'})) {
        unless (defined($this->{'module'}->{'actions'}->{$action}->{'desc'})) {
          $this->{'module'}->{'actions'}->{$action}->{'desc'} =
            'No description';
        }
        push(@actions,$action);
      }
    }
    foreach ( sort(@actions) ) {
      printf("%-16s%-64s\n",$_,
      $this->{'module'}->{'actions'}->{$_}->{'desc'});
    }
  } else {
    my @services;
    foreach my $service (keys %{$this->{'services'}}) {
      push(@services,$service);
    }
    foreach ( sort(@services) ) {
      printf("%-16s%-24s\n",$_,$this->{'services'}->{$_}->{'name'});
    }
    print "\nRun without action for list of available actions for that service.";
  }
  print "\n";
  return;
}

sub do_log ($this, $message, $given_set, $priority = 'info') {
  unless ( defined($this->{'module'}) ) {
    $this->{'module'} = $this;
  }

  foreach my $set ( split( /,/, $this->{'module'}->{'log_sets'} ) ) {
    if ( $set eq 'all' || !defined($given_set) || $set eq $given_set ) {
      if ( $log_levels->{$priority} <= $log_levels->{$this->{'module'}->{'loglevel'}} ) {
        confirmed_log($this,$message);
      }
      last;
    }
  }
  return;
}

sub confirmed_log ($this, $message) {
  foreach my $line ( split( /\n/, $message ) ) {
    if ( $this->{'module'}->{'logfile'} ne '' ) {
      $this->write_log($line);
    }
    if ( $this->{'module'}->{'syslog_facility'} ne '' && $this->{'module'}->{'syslog_progname'} ne '' ) {
      syslog( 'info', '(' . $this->get_thread_id() . ') ' . $line );
    }
  }
  return;
}

sub write_log ($this, $message) {
  chomp($message);
  return if ( $this->{'module'}->{'logfile'} eq '' );

  my $LOCK_SH = 1;
  my $LOCK_EX = 2;
  my $LOCK_NB = 4;
  my $LOCK_UN = 8;
  $| = 1; ## no critic

  if ( !defined( fileno($LOGGERLOG) ) || !-f $this->{'module'}->{'logfile'} ) {
    open($LOGGERLOG, ">>", $this->{'module'}->{'logfile'});
    if ( !defined( fileno($LOGGERLOG) ) ) {
      open $LOGGERLOG, ">>", "/tmp/" . $this->{'module'}->{'logfile'};
      $| = 1; ## no critic
    }
    $this->do_log( 'Log file has been opened, hello !', 'daemon' );
  }
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
  $mon++;
  $year += 1900;
  my $date = sprintf( "%d-%.2d-%.2d %.2d:%.2d:%.2d", $year, $mon, $mday, $hour, $min, $sec );
  flock( $LOGGERLOG, $LOCK_EX );
  print $LOGGERLOG "$date (" . $this->get_thread_id() . ") " . $message . "\n";
  flock( $LOGGERLOG, $LOCK_UN );
  return;
}

sub get_thread_id ($this) {
  my $thread = threads->self;
  return $thread->tid();
}

1;
__END__

=head1 NAME

SpamTagger Service Management

=head1 SYNOPSIS

Load package

  use ManageServices;

Create object (enable auto_start for services that are not running)

  my $manager = ManageServices->( 'auto_start' => 1 ) || die "$!\n";

If the object is created with the 'auto_start' option enabled, services will
be restarted when possible, including with 'check_all', 'status', and 'pids'.

Object contains a list of services as a hash

  foreach my $service (keys(%{$manager->{'services'}})) {
    print "Key: " . $service . "\n";
    print "Name: " . $manager->{'services'}->{$service}->{'name'} . "\n";
  }

All individual actions will return the current state of the service after the
action has been processed. The state is represented by a code. You can get all
available codes from

        foreach my $code (keys(%{$manager->{'codes'}})) {
                print "Code: " . $code . "\n";
                print "Meaning: " . $manager->{'codes'}->{$code}->{'verbose'} . "\n";
        }

Except when using the check_all function, you need to load your desired service

  $manager->load_module($service);

Upon loading the module, it will be available as a nested object. You can find
the last known state of the module with

  $manager->{'module'}->{'state'};

Although it is better to freshly retrieve the state with

  $manager->status();

For this and the other core functions you can simply run them on the base object

  $manager->start();
  $manager->stop();
  $manager->restart();
  $manager->enable();
  $manager->disable();
  $manager->pids();

Each module is capable of loading custom actions that may not exist for other
services. When the module is loaded, all available actions, including the
universal ones, will be loaded into the 'module' member as an 'actions' has

  foreach my $action (keys(%{$manager->{'module'}->{'actions'}) {
    print "Action: " . $action . "\n";
    print "Description: " .
      $manager->{'module'}->{'actions'}->{$action}->{'desc'} . "\n";
  }

In order to run these custom actions you must execute the 'cmd' member of that
hash which will be a code refernce within that specific module. This requires
that the base object be provided as an argument so that the child object has
access to all the parent functions.

  $manager->{'module'}->{'actions'}->{'custom_action'}->{'cmd'}($manager);

Finally, there is the 'check_all' function which will return a hashref of the
status of all available services.

  my $status = $manager->check_all();

  foreach my $service (keys(%$status)) {
    print "$service: " .
      $manager->{'codes'}->{$status->{$service}}->{'verbose'} . "\n";
  }

=head1 DESCRIPTION

This module provides a robust way to manage services while removing ambiguity
as to the success of an action or subsequent changes to a services state for
all or select SpamTagger services.

=head2 EXPORT

none.

=back

=head1 AUTHOR

John Mertz <git@john.me.tz>

=head1 COPYRIGHT AND LICENSE

SpamTagger Plus - Open Source Spam Filtering
Copyright (C) 2025 by John Mertz <git@john.me.tz>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

=cut
