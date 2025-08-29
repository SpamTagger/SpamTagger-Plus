#!/usr/bin/env perl

package MailScanner::MailFilters;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use IO();
use POSIX qw(:signal_h); # For Solaris 9 SIG bug workaround
use MailFilters();

my $MODULE = "MailFilters";
my %conf;
my $mfinterface;

sub initialise {
  MailScanner::Log::InfoLog("$MODULE module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$MODULE.cf";
  %MailFilters::conf = (
     header => "X-$MODULE",
     putHamHeader => 0,
     putSpamHeader => 1,
     maxSize => 0,
     active => 1,
     timeOut => 10,
     server_host => 'localhost',
     server_port => 25080,
     threshold => 0,
     serial => '',
     decisive_field => 'none',
     pos_text => '',
     neg_text => '',
     pos_decisive => 0,
     neg_decisive => 0,
     position => 0
  );

  my $CONFIG;
  if (open($CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $MailFilters::conf{$1} = $2;
      }
    }
    close $CONFIG;
  } else {
    MailScanner::Log::WarnLog("$MODULE configuration file ($configfile) could not be found !");
  }

  $mfinterface = MailFilters::SpamCureClientInterface->new();
  $mfinterface->Initialize($MailFilters::conf{'serial'}, $MailFilters::conf{'server_host'}, $MailFilters::conf{'server_port'});

  if ($MailFilters::conf{'pos_decisive'} && ($MailFilters::conf{'decisive_field'} eq 'pos_decisive' || $MailFilters::conf{'decisive_field'} eq 'both')) {
    $MailFilters::conf{'pos_text'} = 'position : '.$MailFilters::conf{'position'}.', spam decisive';
  } else {
    $MailFilters::conf{'pos_text'} = 'position : '.$MailFilters::conf{'position'}.', not decisive';
  }
  if ($MailFilters::conf{'neg_decisive'} && ($MailFilters::conf{'decisive_field'} eq 'neg_decisive' || $MailFilters::conf{'decisive_field'} eq 'both')) {
    $MailFilters::conf{'neg_text'} = 'position : '.$MailFilters::conf{'position'}.', ham decisive';
  } else {
    $MailFilters::conf{'neg_text'} = 'position : '.$MailFilters::conf{'position'}.', not decisive';
  }
  return;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic

  ## check maximum message size
  my $maxsize = $MailFilters::conf{'maxSize'};
  if ($maxsize > 0 && $message->{size} > $maxsize) {
     MailScanner::Log::InfoLog(
       "Message %s is too big for MailFilters checks (%d > %d bytes)",
       $message->{id}, $message->{size}, $maxsize
     );
     $global::MS->{mta}->AddHeaderToOriginal($message, $MailFilters::conf{'header'}, "too big (".$message->{size}." > $maxsize)");
     return 0;
  }

  if ($MailFilters::conf{'active'} < 1) {
    MailScanner::Log::WarnLog("$MODULE has been disabled");
    $global::MS->{mta}->AddHeaderToOriginal($message, $MailFilters::conf{'header'}, "disabled");
    return 0;
  }

  ### check against MailFilters
  my @whole_message;
  push(@whole_message, $global::MS->{mta}->OriginalMsgHeaders($message, "\n"));
  push(@whole_message, "\n");
  $message->{store}->ReadBody(\@whole_message, 0);
  my $msg = "";
  $msg .= $_ foreach (@whole_message);

  my $tags = '';
  my $result = $mfinterface->ScanSMTPBuffer($msg, $tags);

  if ($result <= 0)  {
    MailScanner::Log::InfoLog("$MODULE returned an error (".$result.")");
    $global::MS->{mta}->AddHeaderToOriginal($message, $MailFilters::conf{'header'}, 'returned an error ('.$result.')');
    return 0;
  }

  if ($result == 2) {
    MailScanner::Log::InfoLog("$MODULE result is spam (".$result.") for ".$message->{id});
    if ($MailFilters::conf{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $MailFilters::conf{'header'}, "is spam ($result, ".$MailFilters::conf{'pos_text'}. ")");
    }
    $message->{prefilterreport} .= ", $MODULE ($result, ".$MailFilters::conf{'pos_text'}.")";
    return 1;
  } else {
    MailScanner::Log::InfoLog("$MODULE result is not spam (".$result.") for ".$message->{id});
    if ($MailFilters::conf{'putHamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $MailFilters::conf{'header'}, "is not spam ($result, ".$MailFilters::conf{'pos_text'}. ")");
    }
  }
  return 0;
}

sub dispose {
  MailScanner::Log::InfoLog("$MODULE module disposing...");
  return;
}

1;
