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
#   This module will just read the configuration file
#

package          SNMPAgent;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use NetSNMP::agent;
use NetSNMP::OID (':all');
use NetSNMP::agent (':all');
use NetSNMP::ASN (':all');
use Sys::Syslog qw(openlog syslog);
use lib '/usr/spamtagger/lib';
use DB();
use ReadConfig();
use Module::Pluggable search_path => ['SNMPAgent'], require => 1;

my $rootoid = ".1.3.6.1.4.1.36661";
our $LOGGERLOG;

## debug
my $logfile = '/tmp/snmpd.debug';
my %log_prio_levels = ( 'error' => 0, 'info' => 1, 'debug' => 2 );
my $log_sets = 'all';
my $log_priority = 'info';
my @logged_sets;
my $prog_name = "SpamTagger SNMP";
my $syslog_progname = '';
my $syslog_facility = '';
my $initialized = 0;

my %mib = ();

sub init ($class) {
  return if ($initialized);
  $initialized = 1;

  my $this = bless {}, $class;

  ## set our process name
  $0 = $syslog_progname; ## no critic
  if ( $syslog_progname eq '' ) {
    $syslog_progname = $class;
  }

  do_log("$syslog_progname Initializing...", 'daemon', 'debug');

  unless (%mib) {
    foreach my $plugin ($this->plugins()) {
      print STDERR "Found plugin: $plugin\n";
      my ($short) = $plugin =~ /::([^:]+)$/;

      my $position = $plugin->init_agent();
      $mib{$position} = $plugin->get_mib() unless (defined($mib{position}));
    }
  }

  my $agent = NetSNMP::agent->new(
    'dont_init_agent' => 1,
    'dont_init_lib' => 1
  );

  my $regoid = NetSNMP::OID->new($rootoid);
  $agent->register($syslog_progname, $regoid, \&snmp_handler);
  if ($@) {
    print STDERR "Registration Error: $@\n";
  }

  ## init syslog if required
  if ( $syslog_facility ne '' ) {
    openlog( $syslog_progname , 'ndelay,pid,nofatal', $syslog_facility );
  }

  do_log("$syslog_progname Initialized.", 'daemon', 'debug');
  return;
}

sub snmp_handler ($handler, $registration_info, $request_info, $requests) {

  for (my $request = $requests; $request; $request = $request->next()) {

    my $oid = $request->get_oid();
    if ($request_info->get_mode() == MODE_GET) {

      do_log("GET : $oid", 'daemon', 'debug');
      my $value_call = get_value_for_oid($oid);
      if (defined($value_call)) {
        my ($type, $value) = $value_call->($oid);
        do_log("type: $type => $value", 'oid', 'debug');
        $request->set_value($type, $value);
      }
    }
    if ($request_info->get_mode() == MODE_GETNEXT) {
      do_log("GETNEXT : $oid", 'daemon', 'debug');

      my $nextoid = get_next_for_oid($oid);
      if (defined($nextoid)) {
        my $value_call = get_value_for_oid(NetSNMP::OID->new($nextoid));
        if (defined($value_call)) {
          my ($type, $value) = $value_call->(NetSNMP::OID->new($nextoid));
          do_log("type: $type => $value", 'oid', 'debug');
          $request->set_oid($nextoid);
          $request->set_value($type, $value);
        }
      }
    }
  }
  return;
}

sub get_value_for_oid ($oid) {
  my $el = get_oid_element($oid);
  return $el if (ref($el) eq 'CODE');
  return;
}

sub get_oid_element ($oid) {
  do_log("Getting element for oid : $oid", 'oid', 'debug');
  my @oid = $oid->to_array();
  my $regoid = NetSNMP::OID->new($rootoid);
  my @rootoid = $regoid->to_array();

  my @local_oid = splice(@oid, @rootoid);

  my $branch = \%mib;
  foreach my $b (@local_oid) {
    return unless (ref($branch) eq 'HASH');
    return unless (defined($branch->{$b}));
    $branch = $branch->{$b};
  }
  return $branch;
}

sub get_next_for_oid ($oid, $nextbranch) {
  return if (NetSNMP::OID->new($oid) < NetSNMP::OID->new($rootoid));
  my $el = get_oid_element(NetSNMP::OID->new($oid));
  if (defined($el) && ref($el) eq 'HASH' && (!defined($nextbranch) || !$nextbranch)) {
    # searching inside
    do_log("is HASH, looking inside $oid", 'oid', 'debug');
    return $oid.".".get_next_element_in_branch($el);
  } else {
    # look into current branch for next
    my $oido = NetSNMP::OID->new($oid);
    my @oida = $oido->to_array();
    my $pos = pop(@oida);
    $oid = join('.', @oida);
    my $branch = get_oid_element(NetSNMP::OID->new($oid));
    #foreach my $selpos (sort(keys(%{$branch}))) {
    foreach my $selpos ( sort { $a <=> $b} keys %{$branch} ) {
      if ($selpos > $pos) {
        do_log("Got a higer element at pos $oid.$selpos", 'oid', 'debug');
        my $sel = get_oid_element(NetSNMP::OID->new("$oid.$selpos"));
        return "$oid.$selpos" if (ref($sel) eq 'CODE');
        if (ref($sel) eq 'HASH') {
          my $tpos = get_next_element_in_branch($sel);
          return $oid.".".$selpos.".".$tpos if (defined($tpos));
          return;
        }
      }
    }
    # if nobody, pop to higer level
    if ($oid ne '') {
      do_log('got to jump higher of '.$oid, 'oid', 'debug');
      return get_next_for_oid($oid, 1);
    }
    return;
  }
}

sub get_next_element_in_branch ($branch) {
  return if ( ref($branch) ne 'HASH');
  foreach my $e ( sort { $a <=> $b} keys %{$branch} ) {
    return $e if (ref($branch->{$e}) eq 'CODE');
    if (ref($branch->{$e}) eq 'HASH') {
      return $e.".".get_next_element_in_branch($branch->{$e});
    }
  }
  return;
}
##### Log management

## add log_sets
foreach my $set ( split( /,/, $log_sets ) ) {
  push @logged_sets, $set;
}
my $log_prio_level = $log_prio_levels{ $log_priority };

sub do_log ($message, $given_set, $priority = 'info') {
  foreach my $set ( @logged_sets  ) {
    if ( $set eq 'all' || !defined($given_set) || $set eq $given_set ) {
      do_effective_log($message) if ( $log_prio_levels{$priority} <= $log_prio_level );
      last;
    }
  }
  return;
}

sub do_effective_log ($message) {
  foreach my $line ( split( /\n/, $message ) ) {
    write_log_to_file($line) if ( $logfile ne '' );
    syslog( 'info', $line ) if ( $syslog_facility ne '' && $syslog_progname ne '' );
  }
  return;
}

sub write_log_to_file ($message) {
  chomp($message);

  return unless (defined($logfile) && $logfile ne '' );

  my $LOCK_SH = 1;
  my $LOCK_EX = 2;
  my $LOCK_NB = 4;
  my $LOCK_UN = 8;
  $| = 1; ## no critic

  if ( !defined($LOGGERLOG) || !-f $logfile ) {
    open($LOGGERLOG, ">>", $logfile);
    unless (defined( fileno($LOGGERLOG) ) ) {
      open($LOGGERLOG, ">>", "/tmp/".$logfile);
      $| = 1; ## no critic
    }
    do_log( 'Log file has been opened, hello !', 'daemon' );
  }
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
  $mon++;
  $year += 1900;
  my $date = sprintf( "%d-%.2d-%.2d %.2d:%.2d:%.2d", $year, $mon, $mday, $hour, $min, $sec );
  flock( $LOGGERLOG, $LOCK_EX );
  print $LOGGERLOG "$date " . $message . "\n";
  flock( $LOGGERLOG, $LOCK_UN );
  return;
}

sub close_log ($this) {
  do_log( 'Closing log file now.', 'daemon' );
  close $LOGGERLOG;
  exit;
}

1;
