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

package RRDArchive;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use SNMP();
use Net::SNMP();
use RRDTool::OO();
use File::Path();
use Scalar::Util qw(looks_like_number);

my $rrdstep = 300;
my %host_failed = ();

sub new ($id, $name, $type, $hosts_status) {
  my $conf = ReadConfig::get_instance();

  my @elements;
  my @hosts;
  my @databases;
  my %snmp;
  my %dynamic_vars;

  my $slave_db = DB->db_connect('slave', 'st_config');
  my @hostsa = $slave_db->getListOfHash("SELECT id, hostname FROM slave");
  push @hosts, $_->{'hostname'} foreach (@hostsa);

  my %community = $slave_db->getHashRow("SELECT community FROM snmpd_config");
  my $community = $community{'community'};

  my $spooldir = $conf->get_option('VARDIR')."/spool/newrrds/".$name."_".$type;
  mkpath($spooldir) unless ( -d $spooldir );

  my $this = {
    'id' => $id,
    'name' => $name,
    'type' => $type,
    'spooldir' => $spooldir,
    'elements' => \@elements,
    'hosts' => \@hosts,
    'hosts_status' => $hosts_status,
    'databases' => \@databases,
    'globaldatabase' => undef,
    'snmp' => \%snmp,
    'community' => $community
  };

  bless $this, "RRDArchive";

  return $this;
}

sub add_element ($this, $element) {
  $element->{'name'} =~ s/\s/_/g;
  push @{$this->{'elements'}}, $element;
  return;
}

sub create_databases ($this) {
  foreach my $h (@{$this->{'hosts'}}) {
    my $dbfile = $this->{'spooldir'}."/".$h.".rrd";
    push @{$this->{'databases'}}, {'host' => $h, 'rrd' => $this->create_database($dbfile)};
  }
  my $gdbfile = $this->{'spooldir'}."/global.rrd";
  $this->{'globaldatabase'} = $this->create_database($gdbfile);
  return;
}

sub create_database ($this, $file) {
  my $rrd = RRDTool::OO->new( file => $file );
  return $rrd if ( -f $file);

  ## add elements
  my @options;
  foreach my $element (@{$this->{elements}}) {
    @options = (
      @options,
      data_source => {
        name => $element->{'name'},
        type => $element->{'type'},
        min => $element->{'min'},
        max => $element->{'max'}
      }
    );
  }

  ## add archives

  # hourly values, step 1, rows 500
  my $count = 1;
  my $rows = 500;

  ## daily values
  $count = 1;
  $rows = 8600;
  @options = (
    @options,
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'LAST',
    },
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'AVERAGE',
    },
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'MAX',
    },
  );

  ## weekly values
  $count = 6;
  $rows = 700;
  @options = (
    @options,
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'LAST',
    },
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'AVERAGE',
    },
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'MAX',
    },
  );

  ## monthly values
  $count = 24;
  $rows = 775;
  @options = (
    @options,
    archive  => { rows      => $rows,
      cpoints   => $count,
      cfunc     => 'LAST',
    },
    archive  => { rows      => $rows,
      cpoints   => $count,
      cfunc     => 'AVERAGE',
    },
    archive  => { rows      => $rows,
      cpoints   => $count,
      cfunc     => 'MAX',
    },
  );

  ## yearly values
  $count = 288;
  $rows = 797;
  @options = (
    @options,
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'LAST',
    },
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'AVERAGE',
    },
    archive  => {
      rows      => $rows,
      cpoints   => $count,
      cfunc     => 'MAX',
    },
  );

  ## and create
  $rrd->new(
    step => $rrdstep,
    @options
  );

  foreach my $element (@{$this->{elements}}) {

    if ($element->{'type'} eq 'COUNTER' || $element->{'type'} eq 'DERIVE') {
      my $ret = eval {
        $rrd->tune(dsname => $element->{'name'}, minumum => 0);
        #$rrd->tune(dsname => $element->{'name'}, maximum => 10000);
      }
    }
  }

  return $rrd;
}

sub collect ($this, $dynamic) {

  $this->create_databases()if (!defined($this->{'globaldatabase'}));

  $$dynamic = $this->get_dynamic_oids() if (keys %{$dynamic} < 1);

  my %globalvalues;

  foreach my $db (@{$this->{databases}}) {
    my %values;
    foreach my $element (@{$this->{elements}}) {

      my $value = $this->get_snmp_value($db->{'host'}, $element->{'oid'}, $dynamic);

      $values{$element->{'name'}} = $value;
      $globalvalues{$element->{'name'}} += $value;
    }
    $db->{'rrd'}->update(values => {%values});
  }
  $this->{'globaldatabase'}->update(values => {%globalvalues});
  return;
}

sub get_snmp_value ($this, $host, $oids, $dynamic) {
  if (defined($host_failed{$host}) && $host_failed{$host} > 0) {
    print "Host '$host' is not available!\n";
    return 0;
  }
  $this->connect_snmp($host) if (!defined($this->{snmp}->{$host}));

  my $value;
  my $op = '+';
  foreach my $oid (split /\s([+-])\s/, $oids) {
    if ($oid eq '+') {
      $op = '+';
      next;
    }
    if ($oid eq '-') {
      $op = '-';
      next;
    }
    if ($oid =~ m/__([A-Z_]+)__/ ) {
      $oid =~ s/__([A-Z_]+)__/$dynamic->{$host}{$1}/g;
    }
    my $rvalue = 0;
    $oid = SNMP::translate_obj($oid);
    unless (defined $oid) {
      return 0;
    }
    my $result = $this->{snmp}->{$host}->get_request(-varbindlist => [$oid]);
    my $error = $this->{snmp}->{$host}->error();
    if (defined($error) && ! $error eq "") {
      print "Error found: $error\n";
      $host_failed{$host} = 1;
    } else {
      if ($result && defined($result->{$oid})) {
        $rvalue = $result->{$oid};
      }
    }
    if ($op eq '-') {
      $value -= $rvalue;
    } elsif ($rvalue =~ m/^[0-9.]+$/) {
      $value += $rvalue;
    } else {
      $value += 0;
    }
  }
  return $value;
}

sub connect_snmp ($this, $host) {
  return 1 if (defined($this->{snmp}->{$host}));
  return 0 if ($host_failed{$host});
  my ($session, $error) = Net::SNMP->session(
    -hostname => $host,
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
  $this->{snmp}->{$host} = $session;
  return 1;
}

sub get_dynamic_oids ($this, $dynamic_oids) {
  $this->get_dynamic_oids_for_host($_, $dynamic_oids) foreach (@{$this->{'hosts'}});
  return 1;
}

sub get_dynamic_oids_for_host ($this, $host, $dynamic_oids) {
  $this->connect_snmp($host) unless (defined($this->{snmp}->{$host}));

  my %partitions = ('OS' => '/', 'DATA' => '/var');
  foreach my $part (keys %partitions) {
    ## first find out partition devices
    my $part_index = $this->get_index_of($host, 'UCD-SNMP-MIB::dskPath', $partitions{$part});
    next unless (defined $part_index);
    $dynamic_oids->{$host}->{$part.'_USAGE'} = $part_index;
    my $part_device = $this->get_value_of_oid($host, 'UCD-SNMP-MIB::dskDevice.'.$part_index);
    next until (defined $part_device);
    $dynamic_oids->{$host}->{$part.'_DEVICE'} = $1 if ($part_device =~ m/^\/dev\/(\S+)/ );

    my $ios_index = $this->get_index_of($host, 'UCD-DISKIO-MIB::diskIODevice', $dynamic_oids->{$host}->{$part.'_DEVICE'});
    $dynamic_oids->{$host}->{$part.'_IO'} = $ios_index if (defined $ios_index);
  }

  my %interfaces = ('IF' => 'eth\d+');
  foreach my $int (keys %interfaces) {
    my $if_index = $this->get_index_of($host, 'IF-MIB::ifDescr', $interfaces{$int});
    $dynamic_oids->{$host}->{$int} = $if_index if (defined $if_index);
  }

  return 1;
}

sub get_index_of ($this, $host, $givenbaseoid, $search) {
  $this->connect_snmp($host) unless (defined($this->{snmp}->{$host}));

  return if (!defined $search);

  ## first check for data and os parts
  my $baseoid = SNMP::translate_obj($givenbaseoid);
  return unless (defined $baseoid);

  my $nextoid = $baseoid;
  while (defined($nextoid) && Net::SNMP::oid_base_match($baseoid, $nextoid)) {
    my $result = $this->{snmp}->{$host}->get_next_request(-varbindlist => [$nextoid]);
    if ($result) {
      foreach my $k (keys %{$result}) {
        if ($search && $result->{$k} =~ m/^$search$/) {
          return $1 if ($k =~ m/\.(\d+)$/);
          return $k;
        }
      }
    }
    my @table = $this->{snmp}->{$host}->var_bind_names;
    $nextoid = $table[0];
  }
  return;
}

sub get_value_of_oid ($this, $host, $givenoid) {
  $this->connect_snmp($host) unless (defined($this->{snmp}->{$host}));
  my $oid = SNMP::translate_obj($givenoid);
  return unless (defined $oid);
  my $result = $this->{snmp}->{$host}->get_request(-varbindlist => [$oid]);
  return $result->{$oid} if ($result && defined($result->{$oid}));
  return;
}

1;
