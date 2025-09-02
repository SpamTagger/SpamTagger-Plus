#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004-2014 Olivier Diserens <olivier@diserens.ch>
#   Copyright (C) 2015-2017 Florian Billebault <florian.billebault@gmail.com>
#   Copyright (C) 2015-2017 Mentor Reka <reka.mentor@gmail.com>
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

package SpamHandler;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use SpamHandler::Batch();
use DB();
use threads();
use threads::shared();
use STDnsLists();

use parent qw(PreForkTDaemon);

my %processed_ids : shared;

sub new ($class = "SpamHandler", $myspec_this = {}) {
  my $conf     = ReadConfig::get_instance();
  my %dbs      = ();
  my %prepared = ();

  my $spec_this = {
    interval => 3,
    spamdir  => $conf->get_option('VARDIR') . '/spool/exim_stage4/spamstore',
    maxbatchsize         => 100,
    reportspamtodnslists => 0,
    reportrbls           => '',
    rblsDefsPath         => $conf->get_option('SRCDIR') . "/etc/rbls/",
    whitelistDomainsFile => $conf->get_option('SRCDIR')
      . "/etc/rbls/whitelisted_domains.txt",
    TLDsFiles => $conf->get_option('VARDIR')
      . "/spool/spamtagger/rbls/two-level-tlds.txt "
      . $conf->get_option('VARDIR')
      . "/spool/spamtagger/rbls/tlds.txt",
    localDomainsFile => $conf->get_option('VARDIR')
      . "/spool/tmp/spamtagger/domains.list",
    maxurisreports => 10,
    configfile     => $conf->get_option('SRCDIR')
      . "/etc/spamtagger/spamhandler.conf",
    pidfile    => $conf->get_option('VARDIR') . "/run/spamhandler.pid",

    %dbs       => (),
    %prepared  => (),
    storeslave => $conf->get_option('HOSTID'),
    clean_thread_exit    => 1,
  };

  # add specific options of child object
  $spec_this->{$_} = $myspec_this->{$_} foreach ( keys(%{$myspec_this}) );

  my $this = $class->SUPER->new('SpamHandler', undef, $spec_this);
  foreach my $key ( keys %{$this} ) {
    $this->{$key} =~ s/%([A-Z]+)%/$conf->get_option($1)/eg;
  }
  return bless $this, $class;
}

sub clear_cache ($this, $nosh, $type) {
  lock(%processed_ids);
  delete $processed_ids{$_} foreach (keys(%processed_ids));
  %processed_ids = ();
  return 1;
}

sub pre_fork_hook ($this) {
  return 1;
}

sub main_loop_hook ($this) {
  $this->do_log( "In SpamHandler mainloop", 'spamhandler' );

  $SIG{'INT'} = $SIG{'KILL'} = $SIG{'TERM'} = sub { ## no critic
    my $t = threads->self;
    $this->{tid} = $t->tid;

    $this->do_log(
      "Thread " . $t->tid . " got TERM! Proceeding to shutdown thread...",
      'daemon'
    );

    threads->detach();
    $this->do_log( "Thread " . $t->tid . " detached.", 'daemon' );
    threads->exit();
    $this->do_log(
      "Huho... Thread " . $t->tid . " still working though...",
      'daemon', 'error'
    );
  };

  ## first prepare databases access for loggin ('_Xname' are for order)
  $this->connect_databases();

  my $spamdir = $this->{spamdir};

  if ( $this->{reportspamtodnslists} > 0 ) {
    $this->{dnslists} =
      STDnsLists->new( sub { my $msg = shift; $this->do_log($msg, 'spamhandler'); },
      $this->{debug} );
    $this->{dnslists}->load_rbls(
      $this->{rblsDefsPath}, $this->{reportrbls},
      'URIRBL',              $this->{whitelistDomainsFile},
      $this->{TLDsFiles},    $this->{localDomainsFile},
      'dnslists'
    );
  }

  while (1) {
    my $batch = SpamHandler::Batch->new($spamdir, $this);
    unless ($batch) {
      $this->do_log(
        "Cannot create spam batch ($spamdir) ! sleeping for 10 seconds...",
        'spamhandler', 'error'
      );
      sleep 10;
      return 0;
    }

    $batch->prepare_run();
    $batch->get_messages_to_process();
    $batch->run();
    sleep $this->{prefork} * $this->{interval};
  }
  $this->do_log( "Error, in thread neverland !", 'spamhandler', 'error' );
  return 1;
}

sub connect_databases ($this) {
  my @databases = ( 'slave', 'realmaster' );

  foreach my $db (@databases) {
    if ( !defined( $this->{dbs}{$db} ) || !$this->{dbs}{$db}->ping() ) {
      $this->do_log( "Connecting to database $db", 'spamhandler' );
      $this->{dbs}{$db} = DB->db_connect( $db, 'st_spool', 0 );
    }

    if ( !defined( $this->{dbs}{$db} ) || !$this->{dbs}{$db}->ping() ) {
      $this->do_log( "Error, could not connect to db $db ",
        'spamhandler', 'error' );
      delete( $this->{dbs}{$db} );
    }
  }

  ## and prepare statements
  foreach my $dbname ( keys %{ $this->{dbs} } ) {
    ## desable autocommit
    $this->{dbs}{$dbname}->set_auto_commit(0);
    my $db = $this->{dbs}{$dbname};
    foreach my $t (
      (
        'a', 'b', 'c',    'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k',    'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's',    't', 'u', 'v', 'w', 'x',
        'y', 'z', 'misc', 'num'
      )
      )
    {
      my %db_prepare = ();
      $this->{prepared}{$dbname}{$t} = $db->prepare(
        'INSERT IGNORE INTO spam_' . $t
          . ' (date_in, time_in, to_domain, to_user, sender, exim_id, M_score, M_rbls, M_prefilter, M_subject, M_globalscore, forced, in_master, store_slave, is_newsletter)
        VALUES(NOW(),   NOW(),     ?,         ? ,     ? ,       ?,      ?,      ?,        ?,          ?,             ?,      \'0\',     ?,'
          . $this->{storeslave} . ', ?)'
      );

      if ( !$this->{prepared}{$dbname}{$t} ) {
        $this->do_log( "Error in preparing statement $dbname, $t!",
          'spamhandler', 'error' );
      }
    }
  }

  return 1;
}

sub delete_lock ($this, $id) {
  lock(%processed_ids);
  delete $processed_ids{$id} if (defined($processed_ids{$id}));
  return 1;
}

sub add_lock ($this, $id) {
  lock(%processed_ids);
  $processed_ids{$id} = 1;
  return 1;
}

sub is_locked ($this, $id) {
  lock(%processed_ids);
  return $processed_ids{$id} if ( exists( $processed_ids{$id} ) );
  return 0;
}

1;
