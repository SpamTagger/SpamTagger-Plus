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

package ManageServices::SpamD;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use parent -norequire qw(ManageServices);

sub init ($module, $class) {
  my $this = $class->SUPER::create_module( config($class) );
  bless $this, 'ManageServices::SpamD';

  return $this;
}

sub config ($class) {
  my $config = {
    'name'     => 'spamd',
    'cmndline'  => 'spamd.pid',
    'cmd'    => '/usr/local/bin/spamd',
    'conffile'  => $class->{'conf'}->get_option('SRCDIR').'/etc/mailscanner/spamd.conf',
    'pidfile'  => $class->{'conf'}->get_option('VARDIR').'/run/spamassassin.pid',
    'logfile'  => $class->{'conf'}->get_option('VARDIR').'/log/mailscanner/spamd.log',
    'socket'  => $class->{'conf'}->get_option('VARDIR').'/run/spamassassin.sock',
    'children'  => 21,
    'user'    => 'spamtagger',
    'group'    => 'spamtagger',
    'siteconfig'  => $class->{'conf'}->get_option('SRCDIR').'/share/spamassassin',
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
  $this->do_log('Dumping MailScanner config...', 'daemon');
  my $dumped = 0;
  my $rc = eval
  {
    require IPC::Run;
    1;
  };
  if ($rc) {
    $dumped = 1 if IPC::Run::run([$this->{'SRCDIR'}.'/bin/dump_custom_spamc_rules.pl'], "2>&1", ">/dev/null");
  } else {
    $dumped = 1 if system($this->{'SRCDIR'}."/bin/dump_custom_spamc_rules.pl 2>&1 >/dev/null");
  }
  $this->do_log('dump_custom_spamc_rules.pl failed', 'daemon') unless ($dumped);
  $dumped = 0;
  if ($rc) {
    $dumped = 1 if IPC::Run::run([$this->{'SRCDIR'}.'/bin/dump_spamc_double_items.pl'], "2>&1", ">/dev/null");
  } else {
    $dumped = 1 if system($this->{'SRCDIR'}."/bin/dump_spamc_double_items.pl 2>&1 >/dev/null");
  }
  $this->do_log('dump_spamc_double_items.pl failed', 'daemon') unless ($dumped);
  $dumped = 0;
  if ($rc) {
    $dumped = 1 if IPC::Run::run([$this->{'SRCDIR'}.'/bin/dump_mailscanner_config.pl'], "2>&1", ">/dev/null");
  } else {
    $dumped = 1 if system($this->{'SRCDIR'}."/bin/dump_mailscanner_config.pl 2>&1 >/dev/null");
  }
  $this->do_log('dump_mailscanner_config.pl failed', 'daemon') unless ($dumped);
  $dumped = 0;
  #if ($rc) {
    #$dumped = 1 if IPC::Run::run(['/usr/bin/pyzor', 'discover'], "2>&1", ">/dev/null");
  #} else {
    #$dumped = 1 if system("/usr/bin/pyzor discover 2>&1 >/dev/null");
  #}
  #$this->do_log('/usr/bin/pyzor discover failed', 'daemon') unless ($dumped);

  return 1;
}

sub pre_fork ($this, $class) {
  return 0;
}

sub main_loop ($this, $class) {
  my $cmd = $this->{'cmd'};
  open(my $CONF, '<', $this->{'conffile'})
    || die "Cannot open config file $this->{'conffile'}";
  while (my $line = <$CONF>) {
    if ($line =~ m/^#/) {
      next;
    } elsif ($line =~ m/^ *$/) {
      next;
    } elsif ($line =~ m/([^=]*) *= *(.*)/) {
      my ($op, $val) = ($1, $2);

      if ($op eq $val || $val eq "yes") {
        $cmd .= ' --' . $op;
      } elsif ($val ne "no") {
        $cmd .= ' --' . $op . '=' . $val;
      }
    } else {
      $this->do_log("Invalid configuration line: $line", 'daemon');
    }
  }
  close($CONF);

  $this->do_log("Running $cmd", 'daemon');
  system(split(/ /, $cmd));

  return 1;
}

1;
