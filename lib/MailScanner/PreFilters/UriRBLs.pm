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

package MailScanner::UriRBLs;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use MIME::Parser();
use Net::IP();
use Net::CIDR::Lite();
use lib '/usr/spamtagger/lib';
use STDnsLists();

my $MODULE = "UriRBLs";
my $dnslists;

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir    = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir . "/$class.cf";
  my %conf = (
    header               => "X-$class",
    putHamHeader         => 0,
    putSpamHeader        => 1,
    maxURIs              => 10,
    maxURIlength         => 200,
    timeOut              => 30,
    rbls                 => '',
    maxrbltimeouts       => 3,
    listeduristobespam   => 1,
    listedemailtobespam  => 1,
    rblsDefsPath         => "/usr/spamtagger/etc/rbs/",
    wantlistDomainsFile => "/var/spamtagger/spool/spamtagger/rbls/wantlisted_domains.txt",
    TLDsFiles            => "/var/spamtagger/spool/spamtagger/rbls/two-level-tlds.txt /var/spamtagger/spool/spamtagger/rbls/tlds.txt",
    localDomainsFile     => "/var/spamtagger/spool/tmp/spamtagger/domains.list",
    resolveShorteners    => 1,
    avoidhosts           => '',
    temporarydir         => '/tmp',
    decisive_field       => 'none',
    pos_text             => '',
    neg_text             => '',
    pos_decisive         => 0,
    neg_decisive         => 0,
    position             => 0
  );

  my $CONFIG;
  if (open($CONFIG, '<', $configfile )) {
    while (<$CONFIG>) {
      if (/^(\S+)\s*\=\s*(.*)$/) {
        $conf{$1} = $2;
      }
    }
    close($CONFIG);
  } else {
    MailScanner::Log::WarnLog("$class configuration file ($configfile) could not be found !");
  }

  $UriRBLs::dnslists = STDnsLists->new( \&MailScanner::Log::WarnLog, $conf{debug} );

  $UriRBLs::dnslists->load_rbls(
    $conf{rblsDefsPath}, $conf{rbls},
    'URIRBL',                     $conf{wantlistDomainsFile},
    $conf{TLDsFiles},    $conf{localDomainsFile},
    $class
  );

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
  my $maxsize     = $this->{'maxSize'};
  my $header_size = 0;
  $header_size = -s $message->{headerspath} if ( -e $message->{headerspath} );
  my $body_size = $message->{size} - $header_size;

  if ( $maxsize > 0 && $body_size > $maxsize ) {
    MailScanner::Log::InfoLog(
      "Message %s is too big for UriRBLs checks (%d > %d bytes)",
      $message->{id}, $message->{size}, $maxsize );
    $global::MS->{mta}->AddHeaderToOriginal(
      $message,
      $this->{'header'},
      "too big (" . $message->{size} . " > $maxsize)"
    );
    return 0;
  }
  my $senderhostname = '';
  my $senderdomain = $message->{fromdomain};
  my $senderip = $message->{clientip};

  ## try to find sender hostname
  ## find out any previous SPF control
  foreach my $hl ($global::MS->{mta}->OriginalMsgHeaders($message)) {
    if ($senderhostname eq '' && $hl =~ m/^Received: from (\S+) \(\[$senderip\]/) {
      $senderhostname = $1;
      MailScanner::Log::InfoLog(blessed($this)." found sender hostname: $senderhostname for $senderip on message ".$message->{id});
    }
    ## we can here because X-SpamTagger-SPF will always be after the Received fields.
    last if ($hl =~ m/^X-SpamTagger-SPF: (.*)/);
  }

  ## check if in avoided hosts
  foreach my $avoidhost ( split(/[\ ,\n]/, $this->{avoidhosts})) {
    if ($avoidhost =~ m/^[\d\.\:\/]+$/) {
      if ($this->{debug}) {
        MailScanner::Log::InfoLog(blessed($this)." should avoid control on IP ".$avoidhost." for message ".$message->{id});
      }
      my $acidr = Net::CIDR::Lite->new();
      my $ret = eval { $acidr->add_any($avoidhost); };
      if ($acidr->find($message->{clientip})) {
        MailScanner::Log::InfoLog(blessed($this)." not checking UriRBL on ".$message->{clientip}." because IP is wantlisted for message ".$message->{id});
        return 0;
      }
    }
    if ($avoidhost =~ m/^[a-zA-Z\.\-\_\d\*]+$/) {
      $avoidhost =~ s/([^\\])\./$1\\\./g;
      $avoidhost =~ s/^\./\\\./g;
      $avoidhost =~ s/([^\\])\*/$1\.\*/g;
      $avoidhost =~ s/^\*/.\*/g;
      if ($this->{debug}) {
        MailScanner::Log::InfoLog(blessed($this)." should avoid control on hostname ".$avoidhost." for message ".$message->{id});
      }
      if ($senderhostname =~ m/$avoidhost$/) {
        MailScanner::Log::InfoLog(blessed($this)." not checking UriRBL on ".$message->{clientip}." because hostname $senderhostname is wantlisted for message ".$message->{id});
        return 0;
      }
    }
  }

  my (@whole_message);
  push( @whole_message, "\n" );
  $message->{store}->ReadBody( \@whole_message, 0 );

  my $parser = MIME::Parser->new();
  $parser->extract_uuencode(1);
  $parser->ignore_errors(1);
  $parser->output_under( $this->{'temporarydir'} );
  my $fullmsg = "";

  $fullmsg .= "$_\n" foreach ($global::MS->{mta}->OriginalMsgHeaders($message));
  $fullmsg .= $_ foreach (@whole_message);
  my $entity = $parser->parse_data($fullmsg);

  my %uris;
  my %emails;
  my %shorts;

  if ($entity->is_multipart) {
    foreach my $part ($entity->parts) {
      if ($part->is_multipart) {
        foreach my $second_part ($part->parts) {
          if ($second_part->effective_type =~ m/^text\//) {
            $this->process_part($message, $second_part, \%uris, \%emails, \%shorts);
          }
        }
      } else {
        if ($part->effective_type =~ m/^text\//) {
          $this->process_part($message, $part, \%uris, \%emails, \%shorts);
        }
      }
    }
  } else {
    $this->process_part($message, $entity, \%uris, \%emails, \%shorts);
  }
  $parser->filer->purge();

  my $uhits      = 0;
  my %urihits    = ();
  my $fullheader = '';
  my $domain     = '';
  foreach my $uri ( keys %uris ) {
    ( $domain, $urihits{$uri}{'count'}, $urihits{$uri}{'header'} ) =
      $UriRBLs::dnslists->check_dns( $uri, 'URIRBL',
      blessed($this)." (" . $message->{id} . ")"
    );
    if ( $urihits{$uri}{'count'} > 0 ) {
      $uhits++;
      $fullheader .= " - " . $domain;
      $fullheader .= "/S" if ( defined( $shorts{$domain} ) );
      $fullheader .= ":" . $urihits{$uri}{'header'};
      if ( $this->{debug} ) {
        MailScanner::Log::InfoLog( blessed($this)." got hit for: $domain ("
          . $urihits{$uri}{'header'} . ") in "
          . $message->{id}
        );
      }
      last if ( $uhits >= $this->{'listeduristobespam'} );
    }
  }
  my $ehits     = 0;
  my %emailhits = ();
  my $emailres  = '';
  foreach my $email ( keys %emails ) {
    ( $emailres, $emailhits{$email}{'count'}, $emailhits{$email}{'header'} )
      = $UriRBLs::dnslists->check_dns( $email, 'ERBL',
      blessed($this)." (" . $message->{id} . ")"
    );
    if ( $emailhits{$email}{'count'} > 0 ) {
      $ehits++;
      $fullheader .= " - " . $email . ":" . $emailhits{$email}{'header'};
      if ( $this->{debug} ) {
        MailScanner::Log::InfoLog( blessed($this)." got hit for: $email ("
          . $emailhits{$email}{'header'} . ") in "
          . $message->{id} );
      }
      last if ( $ehits >= $this->{'listedemailstobespam'} );
    }
  }

  $fullheader =~ s/^\ -\ //;

  if (   $uhits >= $this->{'listeduristobespam'}
    || $ehits >= $this->{'listedemailtobespam'} )
  {
    print "HITS: $uhits-$ehits\n";
    $message->{prefilterreport} .= " ".blessed($this)." ($fullheader, ".$this->{pos_text}.")";
    MailScanner::Log::InfoLog(blessed($this)." result is spam (".$fullheader.") for " . $message->{id} );
    if ( $this->{'putSpamHeader'} ) {
      $global::MS->{mta}->AddHeaderToOriginal(
        $message,
        $this->{'header'},
        "is spam ($fullheader) ".$this->{'pos_text'}
      );
    }
    return 1;
  }
  if ( $this->{'putHamHeader'} ) {
    MailScanner::Log::InfoLog(blessed($this)." result is not spam (".$fullheader.") for " . $message->{id} );
    $global::MS->{mta}->AddHeaderToOriginal(
      $message,
      $this->{'header'},
       "is not spam ($fullheader) ".$this->{'neg_text'}
    );
  }
  return 0;
}

sub dispose ($this) {
  MailScanner::Log::InfoLog(blessed($this)." module disposing...");
  return;
}

sub process_part ($this, $message, $part, $uris, $emails, $shorts) {

  my $body = $part->bodyhandle();
  if (!$body) {

    if ( $this->{debug} ) {
      MailScanner::Log::InfoLog( blessed($this)." cannot find body handle for part: ".$part->effective_type." in ".$message->{id} );
    }
    return 0;
  }

  my $msgtext      = "";
  my $maxuris      = $this->{'maxURIs'};
  my $maxurilength = $this->{'maxURIlength'};

  my $in_header = 1;
  foreach my $line ($body->as_lines) {
    next if ($line =~ m/^\s*$/);
    my $ret =
      $UriRBLs::dnslists->find_uri( $line,
      blessed($this)." (" . $message->{id} . ")" );
    if ($ret) {
      $uris->{$ret} = 1;
      last if ( keys(%{$uris}) >= $maxuris );
    }

    if ( $this->{'resolveShorteners'} ) {
      $ret =
        $UriRBLs::dnslists->find_uri_shortener( $line,
        blessed($this)." (" . $message->{id} . ")"
      );
      if ($ret) {
        $uris->{$ret}   = 1;
        $shorts->{$ret} = 1;
        last if ( keys(%{$uris}) >= $maxuris );
      }
    }

    $ret = $UriRBLs::dnslists->find_email(
      $line,
      blessed($this)." (" . $message->{id} . ")" 
    );

    if ($ret) {
      $emails->{$ret}++;
      last if ( keys(%{$emails}) >= $maxuris );
    }
  }
  return 1;
}

1;
