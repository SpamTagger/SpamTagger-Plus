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

package RRDStats;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use DBI();
use Net::SNMP();

sub new ($hostname) {

  my $conf = ReadConfig::get_instance();
  my $spooldir = $conf->get_option('VARDIR')."/spool/rrdtools/".$hostname;
  my $pictdir = $conf->get_option('VARDIR')."/www/mrtg/".$hostname;
  my %stats = ();

  my $replica_db = DB->db_connect('replica', 'st_config');
  my %row = $replica_db->get_hash_row("SELECT community FROM snmpd_config WHERE set_id=1");
  $replica_db->db_disconnect();
  my $community = $row{'community'};

  my $this = {
    hostname => $hostname,
    spooldir => $spooldir,
    pictdir => $pictdir,
    snmp_session => undef,
    stats => \%stats,
    community => $community
  };
  bless $this, "RRDStats";

  print "WARNING, CANNOT CREATE STAT DIR\n" unless ($this->create_stats_dir());
  print "WARNING, CANNOT CREATE STAT DIR\n" unless ($this->create_graph_dir());
  print "WARNING, CANNOT CONNECT TO SNMP\n" unless ($this->connectSNMP());

  return $this;
}

sub create_rrd ($this, $type) {
  if ($type eq 'cpu') {
    my $res = `uname -r`;
    if ($res =~ m/^2.4/) {
      require RRD::Cpu24;
      $this->{stats}{$type} = &RRD::Cpu24::new($this->{spooldir}, 0);
    } else {
      require RRD::Cpu;
      $this->{stats}{$type} = &RRD::Cpu::new($this->{spooldir}, 0);
    }
  } elsif ($type eq 'load') {
    require RRD::Load;
    $this->{stats}{$type} = &RRD::Load::new($this->{spooldir}, 0);
  } elsif ($type eq 'network') {
    require RRD::Network;
    $this->{stats}{$type} = &RRD::Network::new($this->{spooldir}, 0);
  } elsif ($type eq 'memory') {
    require RRD::Memory;
    $this->{stats}{$type} = &RRD::Memory::new($this->{spooldir}, 0);
  } elsif ($type eq 'disks') {
    require RRD::Disk;
    $this->{stats}{$type} = &RRD::Disk::new($this->{spooldir}, 0);
  } elsif ($type eq 'messages') {
    require RRD::Messages;
    $this->{stats}{$type} = &RRD::Messages::new($this->{spooldir}, 0);
  } elsif ($type eq 'spools') {
    require RRD::Spools;
    $this->{stats}{$type} = &RRD::Spools::new($this->{spooldir}, 0);
  }
  return;
}

sub collect ($this, $type) {
  if (defined($this->{stats}->{$type})) {
    $this->{stats}->{$type}->collect($this->{snmp_session});
  }
  return;
}

sub plot ($this, $type, $mode) {
  my @ranges = ('day', 'week');
  @ranges = ('month', 'year') if ($mode eq 'daily');
  if (defined($this->{stats}->{$type})) {
    for my $time (@ranges) {
     $this->{stats}->{$type}->plot($this->{pictdir}, $time, 1);
    }
  }
  return;
}

sub create_stats_dir ($this) {
  my $conf = ReadConfig::get_instance();
  my $dir = $this->{spooldir};
  return mkdir $dir unless (-d $dir);
  return 1;
}

sub create_graph_dir ($this) {
  my $conf = ReadConfig::get_instance();
  my $dir = $this->{pictdir};
  return mkdir $dir unless (-d $dir);
  return 1;
}

sub connect_snmp ($this) {
  return 1 if (defined($this->{snmp_session}));
  my ($session, $error) = Net::SNMP->session(
    -hostname => $this->{hostname},
    -community => $this->{'community'},
    -port => 161,
    -timeout => 5,
    -version => 2,
    -retries => 1
  );
  unless (defined($session)) {
     print "WARNING, CANNOT CONTACT SNMP HOST\n";
     return 0;
  }
  $this->{snmp_session} = $session;
  return 1;
}

1;
