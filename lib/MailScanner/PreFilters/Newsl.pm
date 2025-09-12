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
#   Newsl prefilter module for MailScanner (Custom version for SpamTagger)

package MailScanner::Newsl;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my $MODULE = "Newsl";
my %conf;

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$class.cf";
  %conf = (
     command => '/usr/local/bin/spamc -R --socket=__NEWSLD_SOCKET__ -s __MAX_SIZE__',
     header => "X-$class",
     putHamHeader => 1,
     putSpamHeader => 1,
     putDetailedHeader => 1,
     scoreHeader => "X-$class-Score",
     maxSize => 0,
     timeOut => 100,
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
       $conf{$1} = $2;
      }
    }
    close $CONFIG;
  } else {
    MailScanner::Log::WarnLog("$class configuration file ($configfile) could not be found !");
  }

  $conf{'command'} =~ s/__CONFIGFILE__/$conf{'configFile'}/g;
  $conf{'command'} =~ s/__NEWSLD_SOCKET__/$conf{'spamdSocket'}/g;
  $conf{'command'} =~ s/__MAX_SIZE__/$conf{'maxSize'}/g;

  # Unless something significant changes, the Newsletter module should NEVER be decisive. It is hard-coded with position 0, so it would override all other modules. There is a separate step to check for newsletters.
  if ($conf{'pos_decisive'} && ($conf{'decisive_field'} eq 'pos_decisive' || $conf{'decisive_field'} eq 'both')) {
    $conf{'pos_text'} = 'position : '.$conf{'position'}.', newsl decisive';
  } else {
    $conf{'pos_text'} = 'position : '.$conf{'position'}.', not decisive';
  }
  if ($conf{'neg_decisive'} && ($conf{'decisive_field'} eq 'neg_decisive' || $conf{'decisive_field'} eq 'both')) {
    $conf{'neg_text'} = 'position : '.$conf{'position'}.', ham decisive';
  } else {
    $conf{'neg_text'} = 'position : '.$conf{'position'}.', not decisive';
  }
  return bless \%conf, $class;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  ## check maximum message size
  my $maxsize = $this->{'maxSize'};
  if ($maxsize > 0 && $message->{size} > $maxsize) {
    MailScanner::Log::InfoLog("Message %s is too big for ".blessed($this)." checks (%d > %d bytes)",
    $message->{id}, $message->{size}, $maxsize);
    $message->{prefilterreport} .= ", ".blessed($this)." (too big)";
    MailScanner::Log::InfoLog(blessed($this)." module checking 2.....");
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "too big (".$message->{size}." > $maxsize)");
    MailScanner::Log::InfoLog(blessed($this)." module checking 3.....");
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
  $ret = -1;
  my $score = 0;
  my $limit = 100;
  my %rules;
  my $rulesum = "NONE";

## analyze result

  @lines = split '\n', $res;
  foreach my $line (@lines) {
    if ($line =~ m/^(.*)\/(.*)$/ ) {
      $score = $1;
      $limit = $2;
      if ($score >= $limit && $limit != 0) {
        $ret = 2;
      } else {
        $ret = 1;
      }
    }
    if ($line =~ m/^(.*=.*)$/ ) {
      $rulesum = $1;
    }
  }

  if ($ret == 2) {
    MailScanner::Log::InfoLog( blessed($this)." result is newsletter ($score/$limit) for " .$message->{id} );
    if ($this->{'putHamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is newsletter ($score/$limit) " .$this->{'pos_text'});
    }
    $message->{prefilterreport} .= ", ".blessed($this)." (score=$score, required=$limit, $rulesum, " .$this->{pos_text}. ")";
    return -1; # Set to 1 to put in spam quarantine, -1 to newsletter
  }

  if ($ret < 0) {
    MailScanner::Log::InfoLog(blessed($this)." result is weird ($lines[0]) for ".$message->{id});
    return 0;
  }

  MailScanner::Log::InfoLog( blessed($this)." result is not newsletter ($score/$limit) for " .$message->{id} );
  if ($this->{'putSpamHeader'}) {
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is not newsletter ($score/$limit) " .$this->{'neg_text'});
  }
  $message->{prefilterreport} .= ", ".blessed($this)." (score=$score, required=$limit, $rulesum, " .$this->{neg_text}. ")";
  return 0;
}

sub dispose ($this) {
  MailScanner::Log::InfoLog(blessed($this)." module disposing...");
  return;
}

1;
