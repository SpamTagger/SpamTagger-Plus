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
#
#   TurstedIPs prefilter module for MailScanner (Custom version for SpamTagger)

package MailScanner::TrustedIPs;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my $MODULE = "TrustedIPs";
my %conf;

sub initialise {
  MailScanner::Log::InfoLog("$MODULE module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$MODULE.cf";
  %TrustedIPs::conf = (
    header => "X-$MODULE",
    putHamHeader => 0,
    putDetailedHeader => 1,
    scoreHeader => "X-$MODULE-score",
    maxSize => 0,
    timeOut => 100,
    debug => 0,
    decisive_field => 'neg_decisive',
    neg_text => '',
    neg_decisive => 0,
    position => 0
  );

  if (open(my $CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $TrustedIPs::conf{$1} = $2;
      }
    }
    close $CONFIG;
  } else {
    MailScanner::Log::WarnLog("$MODULE configuration file ($configfile) could not be found !");
  }

  $TrustedIPs::conf{'neg_text'} = 'position : '.$TrustedIPs::conf{'position'}.', ham decisive';
  return;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  foreach my $hl ($global::MS->{mta}->OriginalMsgHeaders($message)) {
    if ($hl =~ m/^X-SpamTagger-TrustedIPs: Ok/i) {
      my $string = 'sending IP is in Trusted IPs';
      if ($TrustedIPs::conf{debug}) {
          MailScanner::Log::InfoLog("$MODULE result is ham ($string) for ".$message->{id});
      }
      if ($TrustedIPs::conf{'putHamHeader'}) {
        $global::MS->{mta}->AddHeaderToOriginal($message, $TrustedIPs::conf{'header'}, "is ham ($string) ".'position : '.$TrustedIPs::conf{'position'}.', ham decisive');
      }
      $message->{prefilterreport} .= ", $MODULE ($string, ".'position : '.$TrustedIPs::conf{'position'}.', ham decisive'.")";

      return 0;
    }

    if ($hl =~ m/^X-SpamTagger-White-IP-DOM: WhIPDom/i) {
      my $string = 'sending IP is whitelisted for this domain';
      if ($TrustedIPs::conf{debug}) {
          MailScanner::Log::InfoLog("$MODULE result is ham ($string) for ".$message->{id});
      }
      if ($TrustedIPs::conf{'putHamHeader'}) {
        $global::MS->{mta}->AddHeaderToOriginal($message, $TrustedIPs::conf{'header'}, "is ham ($string) ".'position : '.$TrustedIPs::conf{'position'}.', ham decisive');
      }
      $message->{prefilterreport} .= ", $MODULE ($string, ".$TrustedIPs::conf{'position'}.', ham decisive'.")";

      return 0;
    }
  }
  return 1;
}

sub dispose {
  MailScanner::Log::InfoLog("$MODULE module disposing...");
  return;
}

1;
