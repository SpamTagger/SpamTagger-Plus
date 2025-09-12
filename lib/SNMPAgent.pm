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

use DB();
use NetSNMP::agent;
use NetSNMP::OID (':all');
use NetSNMP::agent (':all');
use NetSNMP::ASN (':all');
use lib '/usr/spamtagger/lib';
use ReadConfig();

my $rootoid = ".1.3.6.1.4.1.36661";
our $LOGGERLOG;

## debug
my $logfile = '/tmp/snmpd.debug';
my %log_prio_levels = ( 'error' => 0, 'info' => 1, 'debug' => 2 );
my $log_sets = 'all';
my $log_priority = 'info';
my @logged_sets;
my $syslog_progname = '';
my $syslog_facility = '';

my %mib = ();

sub init {
  doLog('SpamTagger SNMP Agent Initializing...', 'daemon', 'debug');

  my $conf = ReadConfig::get_instance();
  my $agents_dir = $conf->get_option('SRCDIR')."/lib/SNMPAgent/";

  my $dh;
  if (! opendir($dh, $agents_dir)) {
    doLog('No valid agents directory : '.$agents_dir, 'daemon', 'error');
    return 0;
  }
  my @agents;
  while (my $dir = readdir $dh) {
    push @agents, $1 if ($dir =~ m/^([A-Z]\S+).pm$/);
  }
  closedir $dh;

  foreach my $agent (@agents) {
    my $agent_class = 'SNMPAgent::'.ucfirst($agent);

    unless (eval { "require $agent_class" }) {
      die('Agent type does not exists: '.$agent_class);
    }
    my $position = $agent_class->initAgent();
    $mib{$position} = $agent_class->getMIB();
  }

  my $agent = NetSNMP::agent->new(
    'dont_init_agent' => 1,
    'dont_init_lib' => 1
  );

  my $regoid = NetSNMP::OID->new($rootoid);
  $agent->register("SpamTagger SNMP agent", $regoid, \&SNMPHandler);

  doLog('SpamTagger SNMP Agent Initialized.', 'daemon', 'debug');
  return;
}

sub snmp_handler ($handler, $registration_info, $request_info, $requests) {

  for (my $request = $requests; $request; $request = $request->next()) {

    my $oid = $request->getOID();
    if ($request_info->getMode() == MODE_GET) {

      doLog("GET : $oid", 'daemon', 'debug');
      my $value_call = getValueForOID($oid);
      if (defined($value_call)) {
        my ($type, $value) = $value_call->($oid);
        doLog("type: $type => $value", 'oid', 'debug');
        $request->setValue($type, $value);
      }
    }
    if ($request_info->getMode() == MODE_GETNEXT) {
      doLog("GETNEXT : $oid", 'daemon', 'debug');

      my $nextoid = getNextForOID($oid);
      if (defined($nextoid)) {
        my $value_call = getValueForOID(NetSNMP::OID->new($nextoid));
        if (defined($value_call)) {
          my ($type, $value) = $value_call->(NetSNMP::OID->new($nextoid));
          doLog("type: $type => $value", 'oid', 'debug');
          $request->setOID($nextoid);
          $request->setValue($type, $value);
        }
      }
    }
  }
  return;
}

sub get_value_for_oid ($oid) {
  my $el = getOIDElement($oid);
  return $el if (ref($el) eq 'CODE');
  return;
}

sub get_oid_element ($oid) {
  doLog("Getting element for oid : $oid", 'oid', 'debug');
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
  my $el = getOIDElement(NetSNMP::OID->new($oid));
  if (defined($el) && ref($el) eq 'HASH' && (!defined($nextbranch) || !$nextbranch)) {
    # searching inside
    doLog("is HASH, looking inside $oid", 'oid', 'debug');
    return $oid.".".getNextElementInBranch($el);
  } else {
    # look into current branch for next
    my $oido = NetSNMP::OID->new($oid);
    my @oida = $oido->to_array();
    my $pos = pop(@oida);
    $oid = join('.', @oida);
    my $branch = getOIDElement(NetSNMP::OID->new($oid));
    #foreach my $selpos (sort(keys(%{$branch}))) {
    foreach my $selpos ( sort { $a <=> $b} keys %{$branch} ) {
      if ($selpos > $pos) {
        doLog("Got a higer element at pos $oid.$selpos", 'oid', 'debug');
        my $sel = getOIDElement(NetSNMP::OID->new("$oid.$selpos"));
        return "$oid.$selpos" if (ref($sel) eq 'CODE');
        if (ref($sel) eq 'HASH') {
          my $tpos = getNextElementInBranch($sel);
          return $oid.".".$selpos.".".$tpos if (defined($tpos));
          return;
        }
      }
    }
    # if nobody, pop to higer level
    if ($oid ne '') {
      doLog('got to jump higher of '.$oid, 'oid', 'debug');
      return getNextForOID($oid, 1);
    }
    return;
  }
}

sub get_next_element_in_branch ($branch) {
  return if ( ref($branch) ne 'HASH');
  foreach my $e ( sort { $a <=> $b} keys %{$branch} ) {
    return $e if (ref($branch->{$e}) eq 'CODE');
    if (ref($branch->{$e}) eq 'HASH') {
      return $e.".".getNextElementInBranch($branch->{$e});
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
      doEffectiveLog($message) if ( $log_prio_levels{$priority} <= $log_prio_level );
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

  return if ( $logfile eq '' );

  my $LOCK_SH = 1;
  my $LOCK_EX = 2;
  my $LOCK_NB = 4;
  my $LOCK_UN = 8;
  $| = 1; ## no critic

  if ( !defined( fileno($LOGGERLOG) ) || !-f $logfile ) {
    open($LOGGERLOG, ">>", $logfile);
    unless (defined( fileno($LOGGERLOG) ) ) {
      open($LOGGERLOG, ">>", "/tmp/".$logfile);
      $| = 1; ## no critic
    }
    doLog( 'Log file has been opened, hello !', 'daemon' );
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
  doLog( 'Closing log file now.', 'daemon' );
  close $LOGGERLOG;
  exit;
}

1;
