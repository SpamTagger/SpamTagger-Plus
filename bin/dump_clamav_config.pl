#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
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
#   This script will dump the clamav configuration file with the configuration
#   settings found in the database.
#
#   Usage:
#           dump_clamav_config.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use DBI();
use ReadConfig;

our $config = ReadConfig::get_instance();
our $SRCDIR = $config->get_option('SRCDIR');
our $VARDIR = $config->get_option('VARDIR');

my $DEBUG = 1;

my $lasterror;

dump_file("clamav.conf");
dump_file("freshclam.conf");
dump_file("clamd.conf");
dump_file("clamspamd.conf");

# recreate links
my $cmd = "rm /opt/clamav/etc/*.conf >/dev/null 2>&1";
`$cmd`;
$cmd = "ln -s $SRCDIR/etc/clamav/*.conf /opt/clamav/etc/ >/dev/null 2>&1";
`$cmd`;

$cmd = "rm /opt/clamav/share/clamav/* >/dev/null 2>&1";
`$cmd`;
$cmd = "ln -s $VARDIR/spool/clamav/* /opt/clamav/share/clamav/ >/dev/null 2>&1";
`$cmd`;
$cmd = "chown clamav:clamav -R $VARDIR/spool/clamav $VARDIR/log/clamav/ >/dev/null 2>&1";
`$cmd`;

if (-e "$VARDIR/spool/spamtagger/clamav-unofficial-sigs") {
  if (-e "$VARDIR/spool/clamav/unofficial-sigs") {
    my @src = glob("$VARDIR/spool/clamav/unofficial-sigs/*");
    foreach my $s (@src) {
      my $d = $s;
      $d =~ s/unofficial-sigs\///;
      symlink($s, $d) unless (-e $d);
    }
  } else {
    print "$VARDIR/spool/clamav/unofficial-sigs does not exist. Run $SRCDIR/scripts/cron/update_antivirus.sh then try again\n";
  }
} else {
  my @dest = glob("$VARDIR/spool/clamav/*");
  foreach my $d (@dest) {
    my $s = $d;
    $s =~ s/clamav/clamav\/unofficial-sigs/;
    unlink($d) if (-l $d && $s eq readlink($d));
  }
}

print "DUMPSUCCESSFUL\n";

#############################
sub dump_file ($file) {
  my $template_file = "$SRCDIR/etc/clamav/".$file."_template";
  my $target_file = "$SRCDIR/etc/clamav/".$file;

  my $TEMPLATE;
  unless (open($TEMPLATE, '<', $template_file) ) {
    $lasterror = "Cannot open template file: $template_file";
    return 0;
  }
  my $TARGET;
  unless (open($TARGET, ">", "$target_file") ) {
    $lasterror = "Cannot open target file: $target_file";
    close($template_file);
    return 0;
  }

  my $proxy_server = "";
  my $proxy_port = "";
  if ($config->get_option('HTTPPROXY')) {
    if ($config->get_option('HTTPPROXY') =~ m/http\:\/\/(\S+)\:(\d+)/) {
      $proxy_server = $1;
      $proxy_port = $2;
    }
  }

  while($line = <$TEMPLATE>) {
    $line =~ s/__VARDIR__/$VARDIR/g;
    $line =~ s/__SRCDIR__/$SRCDIR/g;
    if ($proxy_server =~ m/\S+/) {
      $line =~ s/\#HTTPProxyServer __HTTPPROXY__/HTTPProxyServer $proxy_server/g;
      $line =~ s/\#HTTPProxyPort __HTTPPROXYPORT__/HTTPProxyPort $proxy_port/g;
    }
    print $TARGET $line;
  }

  if (($file eq "clamd.conf") && ( -e "/var/spamtagger/spool/spamtagger/st-experimental-macros")) {
    print $TARGET "OLE2BlockMacros yes";
  }

  close $TEMPLATE;
  close $TARGET;

  return 1;
}
