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

package ManageServices::NTPD;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use parent -norequire qw(ManageServices);

sub init ($module, $class) {
  my $this = $class->SUPER::create_module( config($class) );
  bless $this, 'ManageServices::NTPD';

  return $this;
}

sub config ($class) {
  my $config = {
    'name'     => 'ntpd',
    'cmndline'  => '/usr/sbin/ntpd',
    'cmd'    => '/usr/sbin/ntpd',
    'pidfile'  => '/var/run/ntpd.pid',
    'user'    => 'ntp',
    'group'    => 'ntp',
    'daemonize'  => 'no',
    'forks'    => 0,
    'syslog_facility' => 'local1',
    'debug'    => 0,
    'log_sets'  => 'all',
    'loglevel'  => 'info',
    'timeout'  => 5,
    'actions'  => {},
  };

  return $config;
}

sub setup ($this, $class) {
  $this->{'cmd'} .= ' -p ' . $self->{'pidfile'} . ' -g -u ' .
    $this->{'uid'} . ':' . $self->{'gid'};

  return 1;
}

sub pre_fork ($this, $class) {
  return 0;
}

sub main_loop ($this, $class) {
  $this->do_log("Running $self->{'cmd'}", 'daemon');
  system($this->{'cmd'});

  return 1;
}

1;
