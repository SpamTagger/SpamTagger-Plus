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

package MailScanner::PreRBLs;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Net::IP();
use Net::CIDR::Lite();
use lib '/usr/spamtagger/lib';
use STDnsLists();

my $MODULE = "PreRBLs";
my %conf;
my %domains_hostname_map_file;

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$class.cf";
  %conf = (
    header => "X-$class",
    putHamHeader => 0,
    putSpamHeader => 1,
    timeOut => 30,
    rbls => '',
    maxrbltimeouts => 3,
    listedtobespam => 1,
    rblsDefsPath => "/usr/spamtagger/etc/rbs/",
    whitelistDomainsFile => "/var/spamtagger/spool/spamtagger/rbls/whitelisted_domains.txt",
    TLDsFiles => "/var/spamtagger/spool/spamtagger/rbls/two-level-tlds.txt /var/spamtagger/spool/spamtagger/rbls/tlds.txt",
    localDomainsFile => "/var/spamtagger/spool/tmp/spamtagger/domains.list",
    domains_hostname_map_file => 'domains_hostnames_map.txt',
    spamhits => 0,
    bsspamhits => 1,
    avoidgoodspf => 0,
    avoidhosts => '',
    debug => 0,
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
    close($CONFIG);
  } else {
    MailScanner::Log::WarnLog("$class configuration file ($configfile) could not be found !");
  }

  my $dnslists = STDnsLists->new(\&MailScanner::Log::WarnLog, $conf{debug});
  $dnslists->load_rbls(
    $conf{rblsDefsPath}, $conf{rbls}, 'IPRBL DNSRBL BSRBL',
    $conf{whitelistDomainsFile}, $conf{TLDsFiles},
    $conf{localDomainsFile}, $class
  );
  $conf{dnslists} = $dnslists;

  if (-f $conf{domains_hostname_map_file}) {
    my $MAPFILE;
    if (open($MAPFILE, '<', $conf{domains_hostname_map_file})) {
      while (<$MAPFILE>) {
        if (/^(\S+),(.*)$/) {
          $domains_hostname_map_file{$1} = $2;
          MailScanner::Log::InfoLog("$class loading domain hostname mapping on $1 to $2");
        }
      }
      close($MAPFILE);
    }
  }

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
  my $senderdomain = $message->{fromdomain};
  my $senderip = $message->{clientip};

  my $continue = 1;
  my $wholeheader = '';
  my $dnshitcount = 0;
  my $senderhostname = '';

  ## try to find sender hostname
  ## find out any previous SPF control
  foreach my $hl ($global::MS->{mta}->OriginalMsgHeaders($message)) {
    if ($senderhostname eq '' && $hl =~ m/^Received: from (\S+) \(\[$senderip\]/) {
      $senderhostname = $1;
      MailScanner::Log::InfoLog("$MODULE found sender hostname: $senderhostname for $senderip on message ".$message->{id});
    }
    if ($hl =~ m/^X-SpamTagger-SPF: (.*)/) {
      if ($1 eq 'pass' && $this->{avoidgoodspf}) {
        MailScanner::Log::InfoLog("$MODULE not checking against: $senderdomain because of good SPF record for ".$message->{id});
        $continue = 0;
      }
      last; ## we can here because X-SpamTagger-SPF will always be after the Received fields.
    }
  }

  my $checkip = 1;
  my ($data, $hitcount, $header);
  ## first check IP
  if ($continue) {
    if ($senderdomain ne '' && ! $this->{dnslists}->is_valid_domain($senderdomain, 1, blessed($this).' domain validator')) {
      my $hostnameregex = $domains_hostname_map_file{$senderdomain};
      if ($hostnameregex &&
        $hostnameregex ne '' &&
        $senderhostname =~ m/$hostnameregex/
      ) {
        MailScanner::Log::InfoLog("$MODULE not checking IPRBL on ".$message->{clientip}." because domain ".$senderdomain." is whitelisted and sender host ".$senderhostname." is from authorized domain for message ".$message->{id});
        $checkip = 0;
      }
    }
    ## check if in avoided hosts
    foreach my $avoidhost (split(/[\ ,\n]/, $this->{avoidhosts})) {
      if ($avoidhost =~ m/^[\d\.\:\/]+$/) {
        if ($this->{debug}) {
          MailScanner::Log::InfoLog("$MODULE should avoid control on IP ".$avoidhost." for message ".$message->{id});
        }
        my $acidr = Net::CIDR::Lite->new();
        my $ret = eval { $acidr->add_any($avoidhost); };
        if ($acidr->find($message->{clientip})) {
          MailScanner::Log::InfoLog("$MODULE not checking IPRBL on ".$message->{clientip}." because IP is whitelisted for message ".$message->{id});
          $checkip = 0;
        }
      }
      if ($avoidhost =~ m/^[a-zA-Z\.\-\_\d\*]+$/) {
        $avoidhost =~ s/([^\\])\./$1\\\./g;
        $avoidhost =~ s/^\./\\\./g;
        $avoidhost =~ s/([^\\])\*/$1\.\*/g;
        $avoidhost =~ s/^\*/.\*/g;
        if ($this->{debug}) {
          MailScanner::Log::InfoLog("$MODULE should avoid control on hostname ".$avoidhost." for message ".$message->{id});
        }
        if ($senderhostname =~ m/$avoidhost$/) {
          MailScanner::Log::InfoLog("$MODULE not checking IPRBL on ".$message->{clientip}." because hostname $senderhostname is whitelisted for message ".$message->{id});
          $checkip = 0;
        }
      }
    }
    if ($checkip) {
      ($data, $hitcount, $header) = $this->{dnslists}->check_dns($message->{clientip}, 'IPRBL', "$MODULE (".$message->{id}.")", $this->{spamhits});
      $dnshitcount = $hitcount;
      $wholeheader .= ','.$header;
      if ($this->{spamhits} && $dnshitcount >= $this->{spamhits} && $this->{'pos_decisive'} == 1) {
  	    $continue = 0;
  	    $message->{isspam} = 1;
  	    $message->{isrblspam} = 1;
      }
    }
  }

  ## second check sender domain
  if ($continue && $this->{dnslists}->is_valid_domain($senderdomain, 1, blessed($this).' domain validator')) {
    ($data, $hitcount, $header) = $this->{dnslists}->check_dns($senderdomain, 'DNSRBL', "$MODULE (".$message->{id}.")", $this->{spamhits});
    $dnshitcount += $hitcount;
    $wholeheader .= ','.$header;
    if ($this->{spamhits} && $dnshitcount >= $this->{spamhits} && $this->{'pos_decisive'} == 1) {
      $continue = 0;
      $message->{isspam} = 1;
      $message->{isrblspam} = 1;
    }
  } elsif ($continue && $this->{debug}) {
    MailScanner::Log::InfoLog("$MODULE not checking DNSBL against: $senderdomain (whitelisted) for ".$message->{id});
  }

  ## third check backscaterrer
  my $bsdnshitcount = 0;
  if ($continue && $message->{from} eq '' && $checkip) {
    ($data, $hitcount, $header) = $this->{dnslists}->check_dns($message->{clientip}, 'BSRBL', "$MODULE (".$message->{id}.")", $this->{spamhits}, $this->{bsspamhits});
    $bsdnshitcount = $hitcount;
    $wholeheader .= ','.$header;
    if ($this->{bsspamhits} && $bsdnshitcount >= $this->{bsspamhits} && $this->{'pos_decisive'} == 1) {
      $continue = 0;
      $message->{isspam} = 1;
      $message->{isrblspam} = 1;
    }
  }

  $wholeheader =~ s/^,+//;
  $wholeheader =~ s/,+$//;
  $wholeheader =~ s/,,+/,/;

  if ($message->{isspam}) {
    MailScanner::Log::InfoLog("$MODULE result is spam ($wholeheader) for ".$message->{id});
    if ($this->{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is spam ($wholeheader) ".$this->{'pos_text'});
    }

    $message->{prefilterreport} .= ", ".blessed($this)." ($wholeheader, ".$this->{'pos_text'}.")";
    return 1;
  }

  if ($wholeheader ne '') {
    MailScanner::Log::InfoLog("$MODULE result is not spam ($wholeheader) for ".$message->{id});
    if ($this->{'putSpamHeader'}) {
       $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is not spam ($wholeheader) ".$this->{'neg_text'});
    }
  }

  return 0;
}

sub dispose ($this) {
  MailScanner::Log::InfoLog("$MODULE module disposing...");
  return;
}

1;
