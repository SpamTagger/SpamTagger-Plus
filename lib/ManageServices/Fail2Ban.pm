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

package ManageServices::Fail2Ban;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use parent -norequire qw(ManageServices);
use Env qw(PYENV_VERSION);

sub init ($module, $class) {
  my $this = $class->SUPER::create_module( config($class) );
  bless $this, 'ManageServices::Fail2Ban';

  return $this;
}

sub config ($class) {
  my $config = {
    'name'     => 'fail2ban',
    'cmndline'  => 'fail2ban-server',
    'cmd'    => '/usr/bin/fail2ban-client',
    'confpath'  => $class->{'conf'}->get_option('USRDIR').'/etc/fail2ban/',
    'logfile'  => $class->{'conf'}->get_option('VARDIR').'/log/fail2ban/st-fail2ban.log',
    'user'    => 'root',
    'group'    => 'root',
    'daemonize'  => 'yes',
    'forks'    => 0,
    'nouserconfig'  => 'yes',
    'syslog_facility' => '',
    'debug'    => 0,
    'log_sets'  => 'all',
    'loglevel'  => 'info',
    'timeout'  => 5,
    'checktimer'  => 10,
    'actions'  => {},
  };

  return $config;
}

sub setup ($this, $class) {
  my $server = $class->SUPER::status('fail2ban-server');
  unless ( $server == 1) {
    $this->do_log("fail2ban-server is not running ($server). Starting...", 'daemon');
    $class->SUPER::start('fail2ban-server');
    # Must reload 'fail2ban' config after operating on 'fail2ban-server'
    $class->SUPER::load_module('fail2ban');
  }

  $this->do_log('Dumping Fail2Ban config...', 'daemon');
  $PYENV_VERSION = '3.7.7';
  if (system($this->{'VARDIR'}.'/.pyenv/shims/dump_fail2ban_config.py')) {
    $this->do_log('dump_fail2ban_config.py failed', 'daemon');
  }

  return 1;
}

sub pre_fork ($this, $class) {
  return 0;
}

sub main_loop ($this, $class) {
  if (!-e $class->{'conf'}->get_option('VARDIR').'/run/fail2ban') {
    mkdir($class->{'conf'}->get_option('VARDIR').'/run/fail2ban')
      || die("Could not create ".$class->{'conf'}->get_option('VARDIR').'/run/fail2ban');
  }
  my $cmd = $this->{'cmd'} . " -c " . $self->{'confpath'} . " start";

  $this->do_log("Running $cmd", 'daemon');
  system(split(/ /,$cmd));

  return 1;
}

1;
