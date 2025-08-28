#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
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

package MailScanner::Profiler;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use vars qw($VERSION);

use Time::HiRes qw(gettimeofday tv_interval);

# Constructor.
sub new (%start_times, %res_times) {
  my $this = {
     %start_times => (),
     %res_times => (),
  };

  bless $this, 'MailScanner::Profiler';
  return $this;
}

sub start ($this, $var) {
  return unless MailScanner::Config::Value('profile');
  $this->{start_times}{$var} = [gettimeofday];
  return;
}

sub stop ($this, $var) {
  return unless MailScanner::Config::Value('profile');

  return unless defined($this->{start_times}{$var});
  my $interval = tv_interval ($this->{start_times}{$var});
  $this->{res_times}{$var} = (int($interval*10000)/10000);
  return;
}

sub get_result ($this) {
  return unless MailScanner::Config::Value('profile');

  my $out = "";

  $out .= " ($key:".$this->{res_times}{$key}."s)" foreach (sort(keys(%{$this->{res_times}})));
  return $out;
}

# TODO: Perl::Critic built-in name confict. Hard-coded in MailScanner?
sub log ($this, $extra) { ## no critic
  return unless MailScanner::Config::Value('profile');

  MailScanner::Log::InfoLog($extra.$this->get_result());
  return 1;
}

1;

