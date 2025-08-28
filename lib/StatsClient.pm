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

package StatsClient;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();

use parent qw(SockClient);

sub new ($class) {
  my %msgs = ();

  my $spec_this = {
     %msgs => (),
     currentid => 0,
     socketpath => '',
     timeout => 5,
     set_timeout => 5,
     get_timeout => 120,
  };

  my $conf = ReadConfig::get_instance();
  $spec_this->{socketpath} = $conf->get_option('VARDIR')."/run/statsdaemon.sock";

  my $this = $class->SUPER::new($spec_this);

  bless $this, $class;
  return $this;
}

sub get_value ($this, $element) {
  $this->{timeout} = $this->{get_timeout};
  my $ret = $this->query('GET '.$element);
  return $ret;
}

sub add_value ($this, $element, $value) {
  $this->{timeout} = $this->{set_timeout};
  my $ret = $this->query('ADD '.$element.' '.$value);
  return $ret;
}

# TODO: This appears to be unused...
sub add_message_stats ($this, $element, $values) {
  my $final_ret = 'ADDED';
  my $nbmessages = 0;
  $values->{'msg'} = 1;
  $values->{'clean'} = 1;

  my @dirtykeys = ('spam', 'highspam', 'virus', 'name', 'other', 'content');
  foreach my $ckey (@dirtykeys) {
    if (defined($values->{$ckey}) && $values->{$ckey} > 0) {
        $values->{'clean'} = 0;
        last;
    }
  }

  foreach my $key (%{$values}) {
    if ($values->{$key}) {
      my $ret = $this->add_value($element.":".$key, $values->{$key});
      if ($key eq 'msg' && $ret =~ /^ADDED\s+(\d+)/) {
        $nbmessages = $1;
      }
      if ($ret !~ /^ADDED/) {
        $final_ret = $ret;
      }
    }
  }
  return $final_ret." ".$nbmessages;
}

sub set_timeout ($this, $timeout) {
   return 0 if ($timeout !~ m/^\d+$/);
   $this->{timeout} = $timeout;
   return 1;
}

sub log_stats ($this) {
   my $query = 'STATS';
   return $this->query($query);
}

1;
