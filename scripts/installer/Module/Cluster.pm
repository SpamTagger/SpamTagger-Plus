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
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

package Module::Cluster;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use lib "/usr/spamtagger/scripts/installer/";
use ReadConfig();
use Exporter();
use DialogFactory();
use Term::ReadKey qw( ReadKey ReadMode );

sub new {
  my $this = {};
  bless $this, 'Module::Cluster';
  return $this;
}

sub run($this) {
  my ($SRCDIR, $MYMAILCLENARPWD);
  my $conf = ReadConfig::get_instance();
  $SRCDIR = $conf->get_option('SRCDIR');
  $MYMAILCLENARPWD = $conf->get_option('MYMAILCLENARPWD') || undef;
  unless (defined($MYMAILCLENARPWD)) {
    print "Database password is not configured in `/etc/mailcleaner.conf`. Please run previous step. [Enter]\n";
    ReadMode 'normal';
    my $null = ReadLine(0);
    return 0;
  }
  `$SRCDIR/scripts/configuration/slaves.pl --setmaster`;
  return;
}

1;
