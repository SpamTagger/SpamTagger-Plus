#!/usr/bin/env perl

package MailScanner::ClamSpam;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my $MODULE = "ClamSpam";
my %conf;

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$class.cf";
  %conf = (
    command => '/usr/bin/clamdscan --no-summary --config-file=__CONFIGFILE__ -',
    header => "X-$class",
    putHamHeader => 0,
    putSpamHeader => 1,
    putDetailedHeader => 1,
    scoreHeader => "X-$class-result",
    maxSize => 0,
    timeOut => 20,
    decisive_field => 'none',
    pos_text => '',
    pos_decisive => 0,
    position => 0
  );

  my $CONFIG;
  if (open($CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
       $conf{$1} = $2;
      }
    }
    close($CONFIG);
  } else {
    MailScanner::Log::WarnLog("$class configuration file ($configfile) could not be found !");
  }
  $conf{'command'} =~ s/__CONFIGFILE__/$conf{'configFile'}/g;
  $conf{'command'} =~ s/__CLAM_DB__/$conf{'clamdb'}/g;

  if ($conf{'pos_decisive'} && ($conf{'decisive_field'} eq 'pos_decisive' || $conf{'decisive_field'} eq 'both')) {
    $conf{'pos_text'} = 'position : '.$conf{'position'}. ', spam decisive';
  } else {
    $conf{'pos_text'} = 'position : '.$conf{'position'}. 'not decisive';
  }
  return bless \%conf, $class;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  ## check maximum message size
  my $maxsize = $this->{'maxSize'};
  if ($maxsize > 0 && $message->{size} > $maxsize) {
    MailScanner::Log::InfoLog("Message %s is too big for ClamSpam checks (%d > %d bytes)",
                              $message->{id}, $message->{size}, $maxsize);
    $message->{prefilterreport} .= ", ClamSpam (too big)";
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "too big (".$message->{size}." > $maxsize)");
    return 0;
  }

  my @whole_message;
  push(@whole_message, $global::MS->{mta}->OriginalMsgHeaders($message, "\n"));
  push(@whole_message, "\n");
  $message->{store}->ReadBody(\@whole_message, 0);

  my $msgtext = "";
  foreach my $line (@whole_message) {
    $msgtext .= $line;
  }

  my $tim = $this->{'timeOut'};
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
    run3 $this->{'command'}, \$msgtext, \$out, \$err;
    $res = $out;
  });
  if ($t->timed_out()) {
    MailScanner::Log::InfoLog(blessed($this)." timed out for ".$message->{id}."!");
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, 'timeout');
    return 0;
  }
  ## not spam per default
  $ret = 1;
  my $spamfound = "";
## analyze result

  @lines = split "\n", $res;
  foreach my $line (@lines) {
    if ($line =~ m/:\s*(\S+)\s+FOUND$/ ) {
      $spamfound .= ", $1";
      $ret = 2;
    }
  }
  $spamfound =~ s/^, //;

  if ($ret == 2) {
    MailScanner::Log::InfoLog(blessed($this)." result is spam ($spamfound) for ".$message->{id});
    if ($this->{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is spam ($spamfound) " .$this->{'pos_text'});
    }
    $message->{prefilterreport} .= ", ClamSpam ($spamfound, " .$this->{pos_text}.")";

    return 1;
  }
  return 0;
}

sub dispose ($this) {
  MailScanner::Log::InfoLog(blessed($this)." module disposing...");
  return;
}

1;
