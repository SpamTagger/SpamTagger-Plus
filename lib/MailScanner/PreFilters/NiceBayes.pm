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

package MailScanner::NiceBayes;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

my $MODULE = "NiceBayes";
my %conf;

sub initialise($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$class.cf";
  %conf = (
    command => '/opt/bogofilter/bin/bogofilter -c __CONFIGFILE__ -v',
    configFile => '/opt/bogofilter/etc/bogofilter.cf',
    header => "X-$class",
    putHamHeader => 0,
    putSpamHeader => 1,
    maxSize => 0,
    active => 0,
    timeOut => 10,
    avoidHeaders => '',
    decisive_field => 'none',
    pos_text => '',
    neg_text => '',
    pos_decisive => 0,
    neg_decisive => 0,
    position => 0
  );

  if (open (my $CONFIG, '<', $configfile)) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
       $conf{$1} = $2;
      }
    }
    close($CONFIG);
  } else {
    MailScanner::Log::WarnLog("$class configuration file ($configfile) could not be found !");
  }
  if (-f $conf{'configFile'}) {
    my $cmd = "grep 'bogofilter_dir' ".$conf{'configFile'}." | cut -d'=' -f2";
    my $database = `$cmd`;
    chomp($database);
    $database .= "/wordlist.db";
    if ( -f $database ) {
      $conf{'active'} = 1;
    } else {
      MailScanner::Log::WarnLog("$class bogofilter database not found (".$database.") ! Disabling $class");
    }
  } else {
    MailScanner::Log::WarnLog("$class bogofilter config file (".$conf{'configFile'}." could not be found ! Disabling $class");
  }

  $conf{'command'} =~ s/__CONFIGFILE__/$conf{'configFile'}/g;

  if ($conf{'pos_decisive'} && ($conf{'decisive_field'} eq 'pos_decisive' || $conf{'decisive_field'} eq 'both')) {
    $conf{'pos_text'} = 'position : '.$conf{'position'}.', spam decisive';
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
    MailScanner::Log::InfoLog(
      "Message %s is too big for NiceBayes checks (%d > %d bytes)",
      $message->{id}, $message->{size}, $maxsize
    );
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "too big (".$message->{size}." > $maxsize)");
    return 0;
  }

  if ($this->{'active'} < 1) {
    MailScanner::Log::WarnLog(blessed($this)." has been disabled (no database ?)");
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "disabled (no database ?)");
    return 0;
  }

  my $msgtext = "";
  my @whole_message;
  my $toadd = 0;
  my @avoidheaders = split /,/, $this->{'avoidHeaders'};
  foreach my $headerline (@{$message->{headers}}) {
    if ($headerline =~ m/^(\S+):/) {
      my $headermatch = $1;
      $toadd = 1;
      foreach my $avoidheader (@avoidheaders) {
        if ($headermatch =~ m/^$avoidheader/i) {
          $toadd = 0;
          last;
        }
      }
      if ($toadd) {
        $msgtext .= $headerline."\n";
      }
    } else {
      if ($toadd) {
        $msgtext .= $headerline."\n";
      }
    }
  }
  $message->{store}->ReadBody(\@whole_message, 0);

  $msgtext .= "\n";
  foreach my $line (@whole_message) {
    $msgtext .= $line;
  }

  my $tim = $this->{'timeOut'};
  use Mail::SpamAssassin::Timeout;
  my $t = Mail::SpamAssassin::Timeout->new({ secs => $tim });
  my $is_prespam = 0;
  my $ret = -5;
  my $res = "";

  $t->run(sub {
    use IPC::Run3;
    my $out;
    my $err;

    $msgtext .= "\n";
    $msgtext =~ s/=[0-9A-F]{2}//g;
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
  if ($res =~ /^X-Bogosity: (Ham|Spam|Unsure), tests=bogofilter, spamicity=([0-9.]+), version=([0-9.]+)$/) {
    $ret = 1;
    $ret = 2 if ($1 eq "Spam");
    $score = int($2*10000) / 100;
  }

  if ($ret == 2) {
    MailScanner::Log::InfoLog(blessed($this)." result is spam ($score%) for ".$message->{id});
    if ($this->{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is spam ($score%) ". $this->{'pos_text'});
    }
    $message->{prefilterreport} .= ", NiceBayes ($score\%, ".$this->{'pos_text'}.")";

    return 1;
  }
  if ($ret < 0) {
    MailScanner::Log::InfoLog(blessed($this)." result is weird ($res ".$this->{'command'}.") for ".$message->{id});
    return 0;
  }
  MailScanner::Log::InfoLog(blessed($this)." result is not spam ($score%) for ".$message->{id});
  if ($this->{'putHamHeader'}) {
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is not spam ($score%) ".$this->{'neg_text'});
  }
  $message->{prefilterreport} .= ", NiceBayes ($score\%, ".$this->{'neg_text'}. ")";

  return 0;
}

sub dispose($this) {
  MailScanner::Log::InfoLog(blessed($this)." module disposing...");
  return;
}

1;
