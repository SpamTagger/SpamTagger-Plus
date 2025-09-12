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

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$class.cf";
  %conf = (
    header => "X-$class",
    putHamHeader => 0,
    putDetailedHeader => 1,
    scoreHeader => "X-$class-score",
    maxSize => 0,
    timeOut => 100,
    debug => 0,
    decisive_field => 'neg_decisive',
    neg_text => '',
    neg_decisive => 0,
    position => 0
  );

  my $CONFIG;
  if (open($CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $conf{$1} = $2;
      }
    }
    close $CONFIG;
  } else {
    MailScanner::Log::WarnLog("$class configuration file ($configfile) could not be found !");
  }

  $conf{'neg_text'} = 'position : '.$conf{'position'}.', ham decisive';
  return bless \%conf, $class;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  foreach my $hl ($global::MS->{mta}->OriginalMsgHeaders($message)) {
    if ($hl =~ m/^X-SpamTagger-TrustedIPs: Ok/i) {
      my $string = 'sending IP is in Trusted IPs';
      if ($this->{debug}) {
          MailScanner::Log::InfoLog(blessed($this)." result is ham ($string) for ".$message->{id});
      }
      if ($this->{'putHamHeader'}) {
        $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is ham ($string) ".'position : '.$this->{'position'}.', ham decisive');
      }
      $message->{prefilterreport} .= ", ".blessed($this)." ($string, ".'position : '.$this->{'position'}.', ham decisive'.")";

      return 0;
    }

    if ($hl =~ m/^X-SpamTagger-White-IP-DOM: WhIPDom/i) {
      my $string = 'sending IP is whitelisted for this domain';
      if ($this->{debug}) {
          MailScanner::Log::InfoLog(blessed($this)." result is ham ($string) for ".$message->{id});
      }
      if ($this->{'putHamHeader'}) {
        $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is ham ($string) ".'position : '.$this->{'position'}.', ham decisive');
      }
      $message->{prefilterreport} .= ", ".blessed($this)." ($string, ".$this->{'position'}.', ham decisive'.")";

      return 0;
    }
  }
  return 1;
}

sub dispose ($this) {
  MailScanner::Log::InfoLog(blessed($this)." module disposing...");
  return;
}

1;
