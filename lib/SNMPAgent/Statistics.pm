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

package SNMPAgent::Statistics;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use lib "/usr/rrdtools/lib/perl/";
use NetSNMP::agent();
use NetSNMP::OID (':all');
use NetSNMP::agent (':all');
use NetSNMP::ASN (':all');
use StatsClient();

my $mib_root_position = 3;

my %mib_global_processed = ();
my %mib_global_refused = ();
my %mib_global_delayed = ();
my %mib_global_relayed = ();
my %mib_global_accepted = ();

my %mib_global = (
  '1' => \%mib_global_processed, '2' => \%mib_global_refused,
  '3' => \%mib_global_delayed, '4' => \%mib_global_relayed,
  '5' => \%mib_global_accepted
);
my %mib_domains = ();
my %mib_domains_table = ('1' => \%mib_domains);
my %mib_statistics = ('1' => \%mib_global, '2' => \%mib_domains_table);

## .1.1
my %smtp_processed_stats = (
  '1' => 'msg',
  '2' => 'clean',
  '3' => 'spam',
  '4' => 'virus',
  '5' => 'name',
  '6' => 'other',
  '7' => 'size',
  '8' => 'user',
  '9' => 'domain'
);
## .1.2
my %smtp_refused_stats = (
  '1' => 'refused',
  '2' => 'refused:rbl',
  '3' => 'refused:host_blocklist',
  '4' => 'refused:relay',
  '5' => 'refused:bad_local_part1+refused:bad_local_part2',
  '6' => 'refused:refused_nonbatv+refused_badbatv',
  '7' => 'refused:sender_blocklist+recipient_blocklist+bad_helo',
  '8' => 'refused:refused_spoofing',
  '9' => 'refused:callout',
  '10'=> 'refused:sender_verify',
  '11'=> 'refused:backscatter',
  '12'=> 'refused:unauthenticated',
  '13'=> 'refused:unencrypted',
  '14'=> 'refused:domain',
  '15'=> 'refused:badspf',
  '16'=> 'refused:badrdns'
);
## .1.3
my %smtp_delayed_stats = (
  '1' => 'delayed',
  '2' => 'delayed:ratelimit',
  '3' => 'delayed:greylist'
);
## .1.4
my %smtp_relayed_stats = (
  '1' => 'relayed',
  '2' => 'relayed:host',
  '3' => 'relayed:authenticated',
  '4' => 'relayed:refused',
  '5' => 'relayed:virus'
);
## .1.5
my %smtp_accepted_stats = (
  '1' => 'accepted'
);

my %domain_stats = (
  '3' => 'msg',
  '4' => 'clean',
  '5' => 'spam',
  '6' => 'virus',
  '7' => 'name',
  '8' => 'other',
  '9' => 'size',
  '10' => 'user',
  '11'=> 'refused',
  '12'=> 'refused_nonbatv+refused_badbatv',
  '13'=> 'refused_spoofing+badrdns+badspf',
  '14'=> 'callout_refused',
  '15'=> 'sender_verify_refused',
  '16'=> 'rbl_refused',
  '17'=> 'brbl_refused',
  '18'=> 'delayed',
  '19'=> 'greylisted'
);

my %domain_statistics = ();

my $conf;
my %domains = ();
my $stats_client;

sub init_agent {
   SNMPAgent::do_log('Agent Statistics initializing', 'statistics', 'debug');

   $conf = ReadConfig::get_instance();

   $stats_client = StatsClient->new();
   return $mib_root_position;
}

sub get_mib {
   populate_global();
   populate_domains();
   return \%mib_statistics;
}

sub populate_global {
  foreach my $s (keys %smtp_processed_stats) {
    $mib_global_processed{$s} = \&getGlobalProcessedStat;
  }
  foreach my $s (keys %smtp_refused_stats) {
    $mib_global_refused{$s} = \&getGlobalRefusedStat;
  }
  foreach my $s (keys %smtp_delayed_stats) {
    $mib_global_delayed{$s} = \&getGlobalDelayedStat;
  }
  foreach my $s (keys %smtp_relayed_stats) {
    $mib_global_relayed{$s} = \&getGlobalRelayedStat;
  }
  foreach my $s (keys %smtp_accepted_stats) {
    $mib_global_accepted{$s} = \&getGlobalAcceptedStat;
  }
  return;
}

sub populate_domains {
  delete $mib_domains{$_} for (keys(%mib_domains));
  delete $domains{$_} for (keys(%domains));

  my $file = $conf->get_option('VARDIR')."/spool/tmp/spamtagger/snmpdomains.list";

  my $f;
  if (open($f, '<', $file)) {
    while (<$f>) {
      if (/^(\d+):(\S+)/) {
        set_domain($1, $2);
        SNMPAgent::do_log('adding: '.$2.' => '.$1,'daemon','debug');
      }
    }
    close($f)
  }
  return;
}

sub set_domain ($id, $domain) {
  $domains{$id} = $domain;
  foreach my $s (keys %domain_stats) {
    $mib_domains{'1'}{$id} = \&getDomainIndex;
    $mib_domains{'2'}{$id} = \&getDomainName;
    $mib_domains{$s}{$id} = \&getDomainStat;
  }
  return;
}

##### Handlers
sub get_domain_index ($oid) {
  my @oid = $oid->to_array();
  my $domain_index = pop(@oid);
  return (ASN_INTEGER, int($domain_index));
}

sub get_domain_name ($oid) {
  my @oid = $oid->to_array();
  my $domain_index = pop(@oid);
  return (ASN_OCTET_STR, $domains{$domain_index});
}

sub get_domain_stat ($oid) {
  my @oid = $oid->to_array();

  my $domain_index = pop(@oid);
  my $stat_el = pop(@oid);
  unless (defined($domain_stats{$stat_el})) {
    return (ASN_COUNTER, int(0));
  }
  unless (defined($domains{$domain_index})) {
    return (ASN_COUNTER, int(0));
  }
  my $total_value = 0;
  foreach my $single_stat (split(/\+/, $domain_stats{$stat_el})) {
    my $st_str = 'domain:'.$domains{$domain_index}.':'.$single_stat;
    my $value = $stats_client->query('GET '.$st_str);
    unless ($value =~ m/^\d+$/) {
      SNMPAgent::do_log('Could not get value from stats daemon for '.$st_str,'daemon','error');
      return (ASN_COUNTER, int(0));
    }
    $total_value += int($value);
  }
  return (ASN_COUNTER, int($total_value));
}

sub get_global_processed_stat ($oid) {
  return get_global_stat($oid, \%smtp_processed_stats, 'global');
}

sub get_global_refused_stat ($oid) {
  return get_global_stat($oid, \%smtp_refused_stats, 'smtp');
}

sub get_global_delayed_stat ($oid) {
  return get_global_stat($oid, \%smtp_delayed_stats, 'smtp');
}

sub get_global_relayed_stat ($oid) {
  return get_global_stat($oid, \%smtp_relayed_stats, 'smtp');
}

sub get_global_accepted_stat ($oid) {
  return get_global_stat($oid, \%smtp_accepted_stats, 'smtp');
}

sub get_global_stat ($oid, $stat_defs, $base) {
  my @oid = $oid->to_array();
  my $stat_el = pop(@oid);

  my $type = ASN_COUNTER;
  unless (defined($stat_defs->{$stat_el})) {
    SNMPAgent::do_log('No such stat element: '.$stat_el);
    return ($type, int(0));
  }

  my $total_value = 0;
  foreach my $single_stat (split(/\+/, $stat_defs->{$stat_el})) {
    my $st_str = $base.':'.$single_stat;
    SNMPAgent::do_log('Querying stat daemon for : '.$st_str,'daemon','debug');
    my $value = $stats_client->query('GET '.$st_str);
    unless ($value =~ m/^\d+$/) {
      SNMPAgent::do_log('Could not get value from stats daemon for '.$st_str,'daemon','error');
      return ($type, int(0));
    }
    $total_value += int($value);
  }
  return ($type, int($total_value));
}

1;
