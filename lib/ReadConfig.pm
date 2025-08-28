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

package ReadConfig;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my $CONFIGFILE = "/etc/spamtagger.conf";
my %config_options;

our $one_true_self;

## singleton stuff
sub get_instance {
  $one_true_self = new() unless ($one_true_self);
  return $one_true_self;
}

## constructor
sub new ($configfile = $CONFIGFILE) {
  return bless { configs => _read_config($configfile) }, "ReadConfig";
}

sub get_option ($this, $option) {
  return $this->{configs}->{$option} if (exists($this->{configs}->{$option}));
  return "";
}

#############################
sub _read_config ($configfile) {
  my ($var, $value);

  open(my $CONFIG, '<', $configfile) or die "Cannot open $configfile: $!\n";
  while (<$CONFIG>) {
    chomp;                  # no newline
    s/#.*$//;               # no comments
    s/^\*.*$//;             # no comments
    s/;.*$//;               # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    my ($var, $value) = split(/\s*=\s*/, $_, 2);
    ## untainting
    if ($value =~ m/(.*)/) {
      $config{$var} = $1;
    }
    $config{$var} = $value;
  }
  close($CONFIG);
  return \%config;
}

1;
