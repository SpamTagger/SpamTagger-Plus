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

package StatsMsg;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my @statdata_ = ('spam', 'highspam', 'virus', 'name', 'other', 'clean', 'bytes');

sub new ($class) {
  my $this = {};

  $this->{$_} = 0 foreach (@statdata_);

  $this->{'msgs'} = 1;

  bless $this, $class;
  return $this;
}

sub set_status ($this, $isspam, $ishigh, $virusinfected, $nameinfected, $otherinfected, $size) {
  $this->set_as_spam() if ($isspam);
  $this->set_as_high_spam() if ($ishigh);
  $this->set_as_virus() if ($virusinfected);
  $this->set_as_name() if ($nameinfected);
  $this->set_as_other() if ($otherinfected);
  $this->set_bytes($size);
  return;
}

sub set_as_spam ($this) {
  $this->{'spam'} = 1;
  return;
}

sub set_as_high_spam ($this) {
  $this->{'highspam'} = 1;
  return;
}

sub set_as_virus ($this) {
  $this->{'virus'} = 1;
  return;
}

sub set_as_name ($this) {
  $this->{'name'} = 1;
  return;
}

sub set_as_other ($this) {
  $this->{'other'} = 1;
  return;
}

sub set_bytes ($this, $bytes) {
  $this->{'bytes'} = $bytes;
  return;
}

sub get_string ($this) {
  $this->{'clean'} = 1;
  if ( $this->{'spam'} + $this->{'highspam'} + $this->{'virus'} + $this->{'name'} + $this->{'ohter'} > 0) {
    $this->{'clean'} = 0;
  }
  my $str = $this->{'msgs'}."|";
  $str .= $this->{$_}."|" foreach (@statdata_);

  $str =~ s/\|$//;
  return $str;
}

sub do_update ($this, $client, $to, $update_domain, $update_global) {
  print STDERR "\ncalled: ".'ADD '.$to.' '.$this->get_string().' '.$update_domain.' '.$update_global."\n";
  return $client->query('ADD '.$to.' '.$this->get_string().' '.$update_domain.' '.$update_global);
}

1;
