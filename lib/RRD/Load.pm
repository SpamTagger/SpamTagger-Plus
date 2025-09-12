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

package RRD::Load;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib";
use RRD::Generic();

sub new ($statfile, $reset) {
  $statfile = $statfile."/load.rrd";

  my %things = (
    load => ['GAUGE', 'AVERAGE']
  );
  my $rrd = RRD::Generic::create($statfile, \%things, $reset);

  my $this = {
    statfile => $statfile,
    rrd => $rrd
  };

  return bless $this, "RRD::Load";
}

sub collect ($this, $snmp) {
  my %things = (
    load => '1.3.6.1.4.1.2021.10.1.3.2'
  );

  return RRD::Generic::collect($this->{rrd}, $snmp, \%things);
}

sub plot ($this, $dir, $period, $leg) {
  my %things = (
    load => ['area', 'EB9C48', 'BA3614', 'Load', 'AVERAGE', '%10.2lf', ''],
  );
  my @order = ('load');

  my $legend = "\t\t     Last\t   Average\t\t  Max\\n";
  return RRD::Generic::plot('load', $dir, $period, $leg, 'System Load', 0, 0, $this->{rrd}, \%things, \@order, $legend);
}

1;
