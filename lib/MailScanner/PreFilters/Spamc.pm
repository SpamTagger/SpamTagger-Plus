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
#   SpamC prefilter module for MailScanner (Custom version for SpamTagger)

package MailScanner::Spamc;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my $MODULE = "Spamc";
my %conf;

sub initialise {
  MailScanner::Log::InfoLog("$MODULE module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$MODULE.cf";
  %Spamc::conf = (
    command => '/usr/local/bin/spamc -R --socket=__SPAMD_SOCKET__ -s __MAX_SIZE__',
    header => "X-$MODULE",
    putHamHeader => 0,
    putSpamHeader => 1,
    putDetailedHeader => 1,
    scoreHeader => "X-$MODULE-score",
    maxSize => 0,
    timeOut => 100,
    decisive_field => 'none',
    pos_text => '',
    neg_text => '',
    pos_decisive => 0,
    neg_decisive => 0,
    position => 0,
  );

  my $CONFIG;
  if (open($CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $Spamc::conf{$1} = $2;
      }
    }
    close $CONFIG;
  } else {
    MailScanner::Log::WarnLog("$MODULE configuration file ($configfile) could not be found !");
  }
  $Spamc::conf{'command'} =~ s/__CONFIGFILE__/$Spamc::conf{'configFile'}/g;
  $Spamc::conf{'command'} =~ s/__SPAMD_SOCKET__/$Spamc::conf{'spamdSocket'}/g;
  $Spamc::conf{'command'} =~ s/__MAX_SIZE__/$Spamc::conf{'maxSize'}/g;

  if ($Spamc::conf{'pos_decisive'} && ($Spamc::conf{'decisive_field'} eq 'pos_decisive' || $Spamc::conf{'decisive_field'} eq 'both')) {
    $Spamc::conf{'pos_text'} = 'position : '.$Spamc::conf{'position'}.', spam decisive';
  } else {
    $Spamc::conf{'pos_text'} = 'position : '.$Spamc::conf{'position'}.', not decisive';
  }
  if ($Spamc::conf{'neg_decisive'} && ($Spamc::conf{'decisive_field'} eq 'neg_decisive' || $Spamc::conf{'decisive_field'} eq 'both')) {
    $Spamc::conf{'neg_text'} = 'position : '.$Spamc::conf{'position'}.', ham decisive';
  } else {
    $Spamc::conf{'neg_text'} = 'position : '.$Spamc::conf{'position'}.', not decisive';
  }
  return;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  ## check maximum message size
  my $maxsize = $Spamc::conf{'maxSize'};
  if ($maxsize > 0 && $message->{size} > $maxsize) {
    MailScanner::Log::InfoLog(
      "Message %s is too big for Spamc checks (%d > %d bytes)",
      $message->{id}, $message->{size}, $maxsize
    );
    $message->{prefilterreport} .= ", Spamc (too big)";
    $global::MS->{mta}->AddHeaderToOriginal($message, $Spamc::conf{'header'}, "too big (".$message->{size}." > $maxsize)");
    return 0;
  }


  my @whole_message;
  push(@whole_message, $global::MS->{mta}->OriginalMsgHeaders($message, "\n"));
  if ($message->{infected}) {
    push(@whole_message, "X-SpamTagger-Internal-Scan: infected\n");
  }
  push(@whole_message, "\n");
  $message->{store}->ReadBody(\@whole_message, 0);

  my $msgtext = "";
  $msgtext .= $_ foreach (@whole_message);

  my $tim = $Spamc::conf{'timeOut'};
  use Mail::SpamAssassin::Timeout;
  my $t = Mail::SpamAssassin::Timeout->new({ secs => $tim });
  my $is_prespam = 0;
  my $ret = -5;
  my $res = "";
  my @lines;

  $t->run(sub {
    use IPC::Run3;
    my $out;
    my $err;

    $msgtext .= "\n";
    run3 $Spamc::conf{'command'}, \$msgtext, \$out, \$err;
    $res = $out;
  });
  if ($t->timed_out()) {
    MailScanner::Log::InfoLog("$MODULE timed out for ".$message->{id}."!");
    $global::MS->{mta}->AddHeaderToOriginal($message, $Spamc::conf{'header'}, 'timeout');
    return 0;
  }
  $ret = -1;
  my $score = 0;
  my $limit = 100;
  my %rules;

## analyze result

  @lines = split '\n', $res;
  foreach my $line (@lines) {
    if ($line =~ m/^\s*(-?\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)\s*$/ ) {
      $score = $1;
      $limit = $2;
      if ($score >= $limit && $limit != 0) {
        $ret = 2;
      } else {
        $ret = 1;
      }
    }
    if ($line =~ /^\s*([- ]?\d+(?:\.\d+)?|[- ]?\d+)\s+([A-Za-z_0-9]+)\s+(.*)$/) {
      $rules{$2} = $1;
      $rules{$2} =~ s/\s//g;
    }
  }
  my $rulesum = "";
  foreach my $r (keys %rules) {
    $rulesum .= ", $r $rules{$r}";
  }
  $rulesum =~ s/^, //;
  if ($rulesum eq "") {
    $rulesum = "NONE";
  }

  if ($ret == 2) {
    MailScanner::Log::InfoLog("$MODULE result is spam ($score/$limit) for ".$message->{id});
    if ($Spamc::conf{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $Spamc::conf{'header'}, "is spam ($score/$limit) ".$Spamc::conf{pos_text});
    }
    $message->{prefilterreport} .= ", Spamc (score=$score, required=$limit, $rulesum, ".$Spamc::conf{pos_text}.")";

    return 1;
  }
  if ($ret < 0) {
    MailScanner::Log::InfoLog("$MODULE result is weird ($lines[0]) for ".$message->{id});
    return 0;
  }
  MailScanner::Log::InfoLog("$MODULE result is not spam ($score/$limit) for ".$message->{id});
  if ($Spamc::conf{'putHamHeader'}) {
    $global::MS->{mta}->AddHeaderToOriginal($message, $Spamc::conf{'header'}, "is not spam ($score/$limit) ".$Spamc::conf{neg_text});
  }
  $message->{prefilterreport} .= ", Spamc (score=$score, required=$limit, $rulesum, ".$Spamc::conf{neg_text}. ")";
  return 0;
}

sub dispose {
  MailScanner::Log::InfoLog("$MODULE module disposing...");
  return;
}

1;
