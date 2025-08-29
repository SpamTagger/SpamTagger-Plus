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

package PrefDaemon;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use DB();
use POSIX();
use Sys::Hostname();
use Socket();
use Symbol();
use IO::Socket::INET();
use Mail::SpamAssassin::Timeout();

our $LOGGERFILE;

sub new ($class) {
  my $conf = ReadConfig::get_instance();
  my $configfile = $conf->get_option('SRCDIR')."/etc/exim/prefDaemon.conf";

  ## default values
  my $pidfile = $conf->get_option('VARDIR')."/run/prefdaemon.pid";
  my $port = 4352;
  my $logfile = $conf->get_option('VARDIR')."/log/spamtagger/prefdaemom.log";
  my $daemontimeout = 1200;
  my $client_timeout = 5;
  my $sockettimeout = 120;
  my $listenmax = 100;
  my $prefork = 5;
  my $debug = 1;
  my $cachesystem = 600;
  my $cachedomain = 120;
  my $cacheuser = 30;
  my $cleancache = 3600;
  my $slave_db;
  my %childrens;
  my %cache;
  my %wwusercache;
  my %wwdomaincache;
  my %wwglobalcache;
  my $wwusercachemax = 100000;
  my $wwdomaincachemax = 10000;
  my $wwglobalcachemax = 1000;
  my $wwcachepos = 120;
  my $wwcacheneg = 120;

  my $this = {
    port => $port,
    server => '',
    pidfile => $pidfile,
    logfile => $logfile,
    daemontimeout => $daemontimeout,
    clienttimeout => $client_timeout,
    sockettimeout => $sockettimeout,
    listenmax => $listenmax,
    debug => $debug,
    prefork => $prefork,
    children => 0,
    basefork => 0,
    inexit => 0,
    cachesystem => $cachesystem,
    cachedomain  => $cachedomain,
    cacheuser => $cacheuser,
    cleancache => $cleancache,
    lastcleanup => 0,
    slave_db => $slave_db,
    childrens => {},
    cache => {},
    time_to_die => 0,
    wwusercache => {},
    wwdomaincache => {},
    wwglobalcache => {},
    wwusercachemax => $wwusercachemax,
    wwdomaincachemax => $wwdomaincachemax,
    wwglobalcachemax => $wwglobalcachemax,
    wwcachepos => $wwcachepos,
    wwcacheneg => $wwcacheneg
  };

  # replace with configuration file values
  my $CONFFILE;
  if (open($CONFFILE, '<', $configfile)) {
    while (<$CONFFILE>) {
      chop;
      next if /^\#/;
      if (/^(\S+)\ ?\=\ ?(.*)$/) {
        if (defined($this->{$1})) {
          $this->{$1} = $2;
        }
      }
    }
    close $CONFFILE;
  }

  return bless $this, $class;
}

sub log_message ($this, $message) {
  if ($this->{debug}) {
    unless (defined(fileno(LOGGERLOG))) {
       open($LOGGERLOG, ">>", "/tmp/".$this->{logfile});
       $| = 1; ## no critic
    }
    my $date=`date "+%Y-%m-%d %H:%M:%S"`;
    chop($date);
    print $LOGGERLOG "$date: $message\n";
  }
  return;
}

######
## startDaemon
######
sub start_daemon ($this) {
  open($LOGGERLOG, ">>", $this->{logfile});

  my $pid = fork();
  die "Couldn't fork: $!" unless (defined($pid));
  if ($pid) {
    exit;
  } else {
    # Dameonize
    POSIX::setsid();

    $this->logMessage("Starting Daemon");

    $SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{ALRM} = sub { $this->parentGotSignal(); }; ## no critic

    #$0 = "PrefDaemon";
    $this->initDaemon();
    $this->launch_children();
    until ($this->{time_to_die}) {
    };
  }
  exit;
}

sub parent_got_signal ($this) {
  $this->{time_to_die} = 1;
  return;
}

sub reaper ($this) {
  $this->logMessage("Got child death...");
  $SIG{CHLD} = sub { $this->reaper(); }; ## no critic
  my $pid = wait;
  $this->{children}--;
  delete $this->{childrens}{$pid};
  if ($this->{time_to_die} < 1 ) {
    $this->logMessage("Not yet death.. relauching new child");
    $this->makeChild();
  }
  return;
}

sub huntsman ($this) {
  local($SIG{CHLD}) = 'IGNORE'; ## no critic
  $this->{time_to_die} = 1;
  $this->logMessage("Shutting down childs");
  kill 'INT' => keys %{$this->{childrens}};
  $this->logMessage("Daemon shut down");
  exit;
}

sub init_daemon ($this) {
  $this->logMessage("Initializing Daemon");
  $this->{server} = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $this->{port},
    Proto     => 'udp'
  ) or die "Couldn't be an udp server on port ".$this->{port}." : $@\n";
  $this->logMessage("Listening on port ".$this->{port});
  return 0;
}

sub launch_children ($this) {
  for (1 .. $this->{prefork}) {
    $this->logMessage("Launching child ".$this->{children}." on ".$this->{prefork}."...");
    $this->makeChild();
  }
  # Install signal handlers
  $SIG{CHLD} = sub { $this->reaper(); }; ## no critic
  $SIG{INT} = sub { $this->huntsMan(); }; ## no critic

  while (1) {
    sleep;
    $this->logMessage("Child death... still: ".$this->{children});
    for (my $i = $this->{children}; $i < $this->{prefork}; $i++) {
       $this->makeChild();
    }
  }
  return;
}

sub make_child ($this) {
  my $this = shift;
  my $pid;
  my $sigset;

  # block signal for fork
  $sigset = POSIX::SigSet->new(SIGINT);
  sigprocmask(SIG_BLOCK, $sigset) or die "Can't block SIGINT for fork: $!\n";

  die "fork: $!" unless defined ($pid = fork);

  if ($pid) {
    # Parent records the child's birth and returns.
    sigprocmask(SIG_UNBLOCK, $sigset) or die "Can't unblock SIGINT for fork: $!\n";
    $this->{childrens}{$pid} = 1;
    $this->{children}++;
    $this->logMessage("Child created with pid: $pid");
    return;
  }
  # Child can *not* return from this subroutine.
  $SIG{INT} = 'DEFAULT'; ## no critic

  # unblock signals
  sigprocmask(SIG_UNBLOCK, $sigset) or die "Can't unblock SIGINT for fork: $!\n";

  $this->connect_db();

  $this->logMessage("In child listening...");
  $this->listenForQuery();
  exit;
}

sub connect_db ($this) {
  $this->{slave_db} = DB->db_connect('slave', 'st_config', 0);
  if ($this->{slave_db}->ping()) {
    $this->logMessage("Connected to configuration database");
    return 1;
  }
  $this->logMessage("WARNING, could not connect to configuration database");
  return 0;
}

sub listen_for_query ($this) {
  my $message;
  my $serv = $this->{server};
  my $MAXLEN = 1024;

  $this->{lastcleanup} = time();
  my $datas;
  while (my $cli = $serv->recv($datas, $MAXLEN)) {
    my($cli_add, $cli_port) =  sockaddr_in($serv->peername);
    $this->manageClient($cli, $cli_port, $datas);
    my $deltaclean = time() - $this->{lastcleanup};
    if ($deltaclean > $this->{cleancache}) {
      $this->logMessage("Global cache cleanup requested.. ($deltaclean)");
      delete($this->{cache});
      $this->{lastcleanup} = time();
    }
  }
  return;
}

sub manage_client ($this, $cli, $cli_add, $datas) {
  alarm $this->{daemontimeout};

  $this->logMessage("Accepting connection");
  if ($datas =~ /^EXIT/) {
    $this->logMessage("Received EXIT command");
    $this->huntsMan();
    exit;
  }
  my $query = $datas;
  if ($query =~ /^HELO\ (\S+)/) {
    $this->{server}->send("NICE TO MEET YOU: $1\n");
    $this->logMessage("Command HELO answered");
  } elsif ($query =~ /^NULL/) {
    $this->{server}->send("\n");
    $this->logMessage("Command NULL answered");
  } elsif ($query =~ /^PREF\ (\S+)\ (\S+)/) {
    ## now fetch the value and return it as fast as possible
    $this->logMessage("Command: pref $2 requested for $1");
    $this->{server}->send($this->fetchPref($1, $2)."\n");
  } elsif ($query =~ /^(WHITE|WARN|BLACK)LIST (\S+)\ (\S+)/) {
    if ($1 eq "WHITE") {
      $this->logMessage("Command: whitelist query: from $3 to $2");
      $this->{server}->send($this->fetchWW('white', $2, $3)."\n");
    } elsif ($1 eq "WARN") {
      $this->logMessage("Command: warnlist query: from $3 to $2");
      $this->{server}->send($this->fetchWW('warn', $2, $3)."\n");
    } elsif ($1 eq "BLACK") {
      $this->logMessage("Command: blacklist query: from $3 to $2");
      $this->{server}->send($this->fetchWW('black', $2, $3)."\n");
    }
  } else {
    $this->logMessage("BAD command found: $query");
    $this->{server}->send("BAD COMMAND\n");
  }
  return;
}

sub fetch_pref ($this, $who, $what) {
  my $cachevalue = $this->getCacheValue($who, $what);
  if ( $cachevalue !~ /^NOCACHE/) {
    $this->logMessage("Using cached value for: $who  /  $what");
    return 'NOTFOUND'  if ($cachevalue eq 'NOTSET');
    return $cachevalue;
  }

  my $res = "BADPREF";
  if ($who =~ /^\S+\@\S+$/) {
    $this->logMessage("Fetching preference for user: $who");
    $res = $this->fetchAddressPref($who, $what);
  } elsif ($who =~ /^\@(\S+)$/) {
    $this->logMessage("Fetching preference for domain: $1");
    $res = $this->fetchDomainPref($1, $what);
  } elsif ($who eq 'global') {
    $this->logMessage("Fetching global preference");
    $res = $this->fetchGlobalPref($what);
  }
  if ($res eq "BADPREF") {
    $this->logMessage("BAD preference who value: $who");
  } elsif ($res eq "NOTFOUND") {
    $this->logMessage("preference NOTFOUND with value: $who");
  } else {
    $this->setCache($who, $what, $res);
  }
  return 'NOTFOUND' if ($res eq 'NOTSET');
  return $res;
}

sub fetch_ww ($this, $type, $dest, $sender) {
  my $atype = 1; # address
  $atype = 2 if ($dest =~ /^\@(\S+)$/); # domain
  $atype = 3 if ($dest eq 'global' || $dest eq '' || $dest eq '_'); # global
  
  my $cachevalue = $this->getWWCacheValues($type, $dest, $sender, $atype);
  if ( $cachevalue !~ /^NOCACHE/) {
    $this->logMessage("Using cached value for: $type  /  $dest - $sender");
    return $cachevalue;
  }

  return $this->fetchDatabaseWW($type, $dest, $sender, $atype);
}

sub fetch_database_ww ($this, $type, $recipient, $sender, $atype) {
  unless ($this->{slave_db}->ping()) {
    return 'NOTFOUND' unless ($this->connect_db());
  }
  $recipient = "" if ($recipient eq "_");
  $sender =~ s/[\/\'\"\<\>\:\;\?\*\%\&\+]//g;
  $recipient =~ s/[\/\'\"\<\>\:\;\?\*\%\&\+]//g;
  my $query = "SELECT sender FROM wwlists WHERE type='$type' AND ( recipient='$recipient' OR recipient='' ) AND status=1";
  my @entries = $this->{slave_db}->getListOfHash($query);
  foreach my $entry (@entries) {
    my %entryv = %$entry;
    my $test = $entryv{sender};
    $test =~ s/(\.)?\*/\\S+/g;
    $test =~ s/[\/\'\"\<\>\:\;\?\*\%\&\+]//g;
    if ($sender =~ /$test/i) {
      $this->setWWCache($type, $recipient, $sender, $atype, 'FOUND');
      return "FOUND";
    }
  }
  $this->setWWCache($type, $recipient, $sender, $atype, 'NOTFOUND');
  return "NOTFOUND";
}

sub fetch_address_pref ($this, $who, $what) {
  unless ($this->{slave_db}->ping()) {
    return 'NOTFOUND' unless ($this->connect_db());
  }

  my $query = "SELECT $what FROM user_pref p, email e WHERE p.id=e.pref AND e.address='$who'";
  my %res = $this->{slave_db}->getHashRow($query);
  return $res{$what} if (defined($res{$what}));
  return "NOTFOUND";
}

sub fetch_domain_pref ($this, $who, $what) {
  unless ($this->{slave_db}->ping()) {
    return 'NOTFOUND' unless ($this->connect_db());
  }

  $what = 'enable_whitelists' if ($what eq 'has_whitelist');
  $what = 'enable_warnlists' if ($what eq 'has_warnlist');
  $what = 'enable_blacklists' if ($what eq 'has_blacklist');
  ## check this domain
  my $query = "SELECT $what FROM domain_pref p, domain d WHERE p.id=d.prefs AND d.name='$who'";
  my %res = $this->{slave_db}->getHashRow($query);
  return $res{$what} if (defined($res{$what}));
  ## check for jocker domain
  $query = "SELECT $what FROM domain_pref p, domain d WHERE p.id=d.prefs AND d.name='*'";
  %res = $this->{slave_db}->getHashRow($query);
  return $res{$what} if (defined($res{$what}));
  ## check for default domain
  my $dd = $this->fetchGlobalPref('default_domain');
  $query = "SELECT $what FROM domain_pref p, domain d WHERE p.id=d.prefs AND d.name='$dd'";
  %res = $this->{slave_db}->getHashRow($query);
  return $res{$what} if (defined($res{$what}));
  return "NOTFOUND";
}

sub fetch_global_pref ($this, $what) {
  unless ($this->{slave_db}->ping()) {
    return 'NOTFOUND' unless ($this->connect_db());
  }
  my $query = "SELECT $what FROM system_conf, antispam, antivirus, httpd_config";
  my %res = $this->{slave_db}->getHashRow($query);
  return $res{$what} if (defined($res{$what}));
  return "NOTFOUND";
}

####################
## cache management
sub get_cache_value ($this, $who, $what) {
  my $timeout = $this->{cacheuser};
  if ($who =~ /^\@/) {
    $timeout = $this->{cachedomain};
  } elsif ($who eq 'global') {
    $timeout = $this->{cachesystem};
  }
  return "NOCACHE" if $timeout < 1;

  my $cachekey = getCacheKey($who, $what);

  if ( defined($this->{cache}{$cachekey}) && $this->{cache}{$cachekey} =~ /^(\d+)\-(.*)/) {
    $this->logMessage("Cache key hit for: $cachekey ($1, $2)");
    my $deltatime = time() - $1;
    return $2 if ($deltatime < $timeout);
    $this->logMessage("Cache key too old: $deltatime s.");
  }
  return "NOCACHE";
}

sub set_cache ($this, $who, $what, $value) {
  my $timeout = $this->{cacheuser};
  if ($who =~ /^\@/) {
    $timeout = $this->{cachedomain};
  } elsif ($who eq 'global') {
    $timeout = $this->{cachesystem};
  }
  return if ($timeout < 1);

  my $cachekey = getCacheKey($who, $what);

  my $time = time();
  $this->{cache}{$cachekey} = $time."-".$value;
  $this->logMessage("Saved cache for: $cachekey");
  return;
}

sub dump_cache ($this) {
  foreach my $key (keys %{$this->{cache}}) {
    $this->logMessage(" === cache key: $key   /  ".$this->{cache}{$key}[1]);
  }
  return;
}

sub get_cache_key ($who, $what) {
  return $who."/".$what;
}

sub get_ww_cache_values ($this, $type, $dest, $sender, $atype) {
  my $cachehash = \%{$this->{wwusercache}};
  if ($atype == 2) {
    if (keys(%{$this->{wwdomaincache}}) > $this->{wwdomaincachemax}) {
      unset ($this->{wwdomaincache});
      $this->logMessage(" Purged ww domain cache, maximum of ".$this->{wwdomaincachemax}." entries reached");
      return "NOCACHE";
    }
    $cachehash = \%{$this->{wwdomaincache}};
  } elsif ($atype == 3) {
    if (keys(%{$this->{wwglobalcache}}) > $this->{wwglobalcachemax}) {
      unset ($this->{wwglobalcache});
      $this->logMessage(" Purged ww global cache, maximum of ".$this->{wwglobalcachemax}." entries reached");
      return "NOCACHE";
    }
    $cachehash = \%{$this->{wwglobalcache}};
  }
  if (keys(%{$this->{wwusercache}}) > $this->{wwusercachemax}) {
    unset ($this->{wwusercache});
    $this->logMessage(" Purged ww user cache, maximum of ".$this->{wwusercachemax}." entries reached");
    return "NOCACHE";
  }

  my $cachekey = getWWCacheKey($type, $dest, $sender);

  if ( defined($cachehash->{$cachekey}) && $cachehash->{$cachekey} =~ /^(\d+)\-(.*)/) {
    $this->logMessage("WW Cache key hit for: $cachekey ($1, $2)");
    my $deltatime = time() - $1;
    my $result = $2;
    if ($result eq "FOUND" && $deltatime > $this->{wwcachepos}) {
      $this->logMessage("WW positive Cache key too old: $deltatime s.");
      return "NOCACHE";
    }
    if ($result eq "NOTFOUND" && $deltatime > $this->{wwcacheneg}) {
      $this->logMessage("WW negative Cache key too old: $deltatime s.");
      return "NOCACHE";
    }
    return $result if ($result =~ /^(NOT)?FOUND$/);
    $this->logMessage(" Illegal WW cache value: $2");
    return "NOCACHE";
  }

  return "NOCACHE";
}

sub set_ww_cache ($this, $type, $dest, $sender, $atype, $value) {
  return if ($value eq "FOUND" && $this->{wwcachepos} < 1);
  return if ($value eq "NOTFOUND" && $this->{wwcacheneg} < 1);
  return if (! $value eq "FOUND" && ! $value eq "NOTFOUND");

  my $cachekey = getWWCacheKey($type, $dest, $sender);

  my $cachehash = \%{$this->{wwusercache}};
  if ($atype == 2) {
    $cachehash = \%{$this->{wwdomaincache}};
  } elsif ($atype == 3) {
    $cachehash = \%{$this->{wwglobalcache}};
  }

  my $time = time();
  $cachehash->{$cachekey} = $time."-".$value;
  $this->logMessage("Saved WW cache for: $cachekey");
  return;
}

sub get_ww_cache_key ($type, $dest, $sender) {
  return $type."/".$dest."/".$sender;
}

###########################
## client call
sub get_pref ($this, $type, $pref) {
  my $res = "NOTFOUND";
  my $t = Mail::SpamAssassin::Timeout->new({ secs => $this->{clienttimeout} });
  $t->run_and_catch( sub { $res = $this->queryDaemon($type, $pref);});

  if ($t->timed_out()) { return "TIMEDOUT"; };
  return $res if (defined($res));
  return 'NOTFOUND';
}

sub query_daemon ($this, $type, $pref) {
  my $socket;
  if ( $socket = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => $this->{port},
    Proto    => "udp")
  ) {
    $socket->send($type." ".$pref."\n");
    my $MAXLEN  = 1024;
    my $response;

    $socket->recv($response, $MAXLEN);
    return "NODAEMON" if ($! !~ /^$/);
    my $res = $response;
    chop($res);
    return $res;
  }
  return "NODAEMON";
}

sub timed_out ($this) {
  exit();
}

1;
