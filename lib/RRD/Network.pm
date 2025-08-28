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

package RRD::Network;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/rrdtools/lib/perl/";
use RRD::Generic();

sub new ($statfile, $reset) {
  $statfile = $statfile."/network.rrd";

  my %things = (
    in => ['COUNTER', 'AVERAGE'],
    out => ['COUNTER', 'AVERAGE']
  );
  my $rrd = RRD::Generic::create($statfile, \%things, $reset);

  my $this = {
    statfile => $statfile,
    rrd => $rrd
  };

  return bless $this, "RRD::Network";
}

sub collect ($this, $snmp) {
  my $if = $this->get_interface_id($snmp, 'eth0');

  my %things = (
    in => '1.3.6.1.2.1.2.2.1.10.'.$if,
    out => '1.3.6.1.2.1.2.2.1.16.'.$if,
  );

  return RRD::Generic::collect($this->{rrd}, $snmp, \%things);
}

sub plot ($this, $dir, $period, $leg) {
  my %things = (
    kbin => ['area', '54EB48', 'BA3614', 'In', 'AVERAGE', '%3.2lf KBps', 'in,1024,/'],
    kbout => ['line', '7648EB', 'BA3614', 'Out', 'AVERAGE', '%3.2lf KBps', 'out,1024,/'],
  );
  my @order = ('kbin', 'kbout');

  my $legend = "\t\t  Last\tAverage\t   Max\\n";
  return RRD::Generic::plot('network', $dir, $period, $leg, 'Bandwidth [KBps]', 0, 0, $this->{rrd}, \%things, \@order, $legend);
}

sub get_interface_id ($this, $snmp, $if_name, $if_nb) {
  my $base_oid = '1.3.6.1.2.1.2.2.1.2';
  for my $i (1..10) {
    my $oid = $base_oid.".$i";
    my $result = $snmp->get_request(
      -varbindlist => [$oid]
    );
    return $if_nb unless (defined($result));
    return $i if ($result->{$oid} eq $if_name);
  }
  return $if_nb;
}

1;
