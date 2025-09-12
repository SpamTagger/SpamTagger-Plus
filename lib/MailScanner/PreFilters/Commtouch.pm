#!/usr/bin/env perl

package MailScanner::Commtouch;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use LWP::UserAgent();
use HTTP::Request::Common();
use Mail::SpamAssassin::Timeout();

my $MODULE = "Commtouch";
my $lwp = LWP::UserAgent->new();

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$class.cf";
  my %conf = (
    header => "X-$class",
    putHamHeader => 0,
    putSpamHeader => 1,
    maxSize => 0,
    active => 1,
    timeOut => 10,
    lwp => undef,
    use_ctaspd => 1,
    ctaspd_server_host => 'localhost',
    ctaspd_server_port => 8088,
    detect_spam_bulk => 1,
    detect_spam_suspected => 0,
    detect_vod_high => 1,
    detect_vod_medium => 0,
    use_ctipd => 1,
    ctipd_server_host => 'localhost',
    ctipd_server_port => 8086,
    ctipd_blocktempfail => 0,
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
  $lwp = LWP::UserAgent->new() || die("Failed to initialize necessary LWP::UserAgent object!");

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
      "Message %s is too big for Commtouch checks (%d > %d bytes)",
      $message->{id}, $message->{size}, $maxsize
    );
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "too big (".$message->{size}." > $maxsize)");
    return 0;
  }

  if ($this->{'active'} < 1) {
    MailScanner::Log::WarnLog(blessed($this)." has been disabled");
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "disabled");
    return 0;
  }

  ### check against ctipd
  my $ctipd_header = '';
  if ($this->{'use_ctipd'}) {
    my $client_ip = $message->{clientip};

    my $url = "http://".$this->{'ctipd_server_host'}.":".$this->{'ctipd_server_port'}."/ctipd/iprep";

    my $request = "x-ctch-request-type: classifyip\r\n".
                  "x-ctch-pver: 1.0\r\n";

    $request .= "\r\n";
    # request body
    $request .= "x-ctch-ip: ".$client_ip."\r\n";

    my $tim = $this->{'timeOut'};
    my $t = Mail::SpamAssassin::Timeout->new({ secs => $tim });
    my $response = "";

    $t->run(sub {
      ## do the job...
      $response = $this->{$lwp}->post($url, Content => $request);
    });
    if ($t->timed_out()) {
      MailScanner::Log::InfoLog(blessed($this)." ctipd timed out for ".$message->{id}."!");
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, 'ctipd timeout');
    } else {
      my $status_line = $response->status_line . "\n";
      chomp $status_line;

      ### parse results:
      my $status = -1; # unknown
      my $status_message = '';

      if ($status_line =~ m/^(\d+)\s+(.*)/) {
        $status = $1;
        $status_message = $2;
      }

      my $res = $response->content;
      if ($status != 200 || $res eq '') {
        MailScanner::Log::InfoLog(blessed($this)." ctipd returned error: ".$status." ".$status_message." for ".$message->{id});
        $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, blessed($this)." ctipd returned error: ".$status." ".$status_message);
      } else {

        my $refid = '';
        my $action_result = '';

        my @res_lines = split('\n', $res);
        foreach my $line (@res_lines) {
          $refid = $1 if ($line =~ m/^X-CTCH-RefID:\s*(.*)/i);
          $action_result = $1 if ($line =~m/^x-ctch-dm-action:\s*(.*)/i);
        }
        $refid =~ s/[\n\r]+//;
        $action_result =~ s/[\n\r]+//;
        $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}."-ctIPd-RefID", $refid);

        if ($action_result eq 'permfail' || ($action_result eq 'tempfail' && $this->{'ctipd_blocktempfail'})) {
          MailScanner::Log::InfoLog(blessed($this)." result is spam (ip: $action_result) for ".$message->{id});
          if ($this->{'putSpamHeader'}) {
            $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is spam (ip: $action_result, ".$this->{pos_text} .")");
          }
          $message->{prefilterreport} .= ", ".blessed($this)." (ip: $action_result, ".$this->{pos_text} .")";
          return 1;
        }
        $ctipd_header = "ip: $action_result" if ($action_result eq 'tempfail');
      }
    }
  }

  $ctipd_header .= ', ' if ($ctipd_header ne '');

  ### check against ctaspd
  if ($this->{'use_ctaspd'}) {
    my @whole_message;
    push(@whole_message, $global::MS->{mta}->OriginalMsgHeaders($message, "\n"));
    push(@whole_message, "\n");
    $message->{store}->ReadBody(\@whole_message, 0);

    my $tim = $this->{'timeOut'};
    my $t = Mail::SpamAssassin::Timeout->new({ secs => $tim });
    my $is_prespam = 0;
    my $ret = -5;
    my $response = "";

    my $request = "X-CTCH-PVer: 0000001\r\n".
                  "X-CTCH-MailFrom: ".$message->{from}."\r\n".
                  "X-CTCH-SenderIP: ".$message->{clientip}."\r\n";

    $request .= "\r\n";
    $request .= $_ foreach (@whole_message);

    my $url = "http://".$this->{'ctaspd_server_host'}.":".$this->{'ctaspd_server_port'}."/ctasd/ClassifyMessage_Inline";

    $t->run(sub {
      ## do the job...
      $response = $this->{lwp}->post($url, Content => $request);
    });

    if ($t->timed_out()) {
      MailScanner::Log::InfoLog(blessed($this)." ctaspd timed out for ".$message->{id}."!");
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, 'ctaspd timeout');
      return 0;
    }
    $ret = -1;
    my $score = 0;

    my $status_line = $response->status_line . "\n";
    chomp $status_line;

    my $res = $response->content;

    ### parse results:
    my $status = -1; # unknown
    my $status_message = '';

    if ($status_line =~ m/^(\d+)\s+(.*)/) {
      $status = $1;
      $status_message = $2;
    }

    if ($status != 200 || $res eq '') {
      MailScanner::Log::InfoLog(blessed($this)." ctaspd returned error: ".$status." ".$status_message." for ".$message->{id});
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, blessed($this)." ctaspd returned error: ".$status." ".$status_message);
      return 0;
    }

    my $spam_result = '';
    my $vod_result = '';
    my $refid = '';

    my @res_lines = split('\n', $res);
    foreach my $line (@res_lines) {
      if ($line =~ m/^X-CTCH-RefID:\s+(.*)/i) {
        $refid = $1;
      }
      if ($line =~m/^X-CTCH-Spam:\s+(.*)/i) {
        $spam_result = $1;
      }
      if ($line =~m/^X-CTCH-VOD:\s+(.*)/i) {
        $vod_result = $1;
        $vod_result = 'Medium';
      }
    }
    $refid =~ s/[\n\r]+//;
    $spam_result =~ s/[\n\r]+//;
    $vod_result =~ s/[\n\r]+//;

    if ($refid eq '') {
      MailScanner::Log::InfoLog(blessed($this)." ctaspd cannot get RefID for ".$message->{id});
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, blessed($this)." ctaspd cannot get RefID");
      return 0;
    }
    $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}."-ctasd-RefID", $refid);

    ## find out spam and VOD positives
    if ($spam_result eq 'Confirmed' ||
      ( $spam_result eq 'Bulk' && $this->{'detect_spam_bulk'}) ||
      ( $spam_result eq 'Suspected' && $this->{'detect_spam_suspected'}) )
    {
      MailScanner::Log::InfoLog(blessed($this)." result is spam (".$ctipd_header."Spam: $spam_result) for ".$message->{id});
      if ($this->{'putSpamHeader'}) {
        $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is spam (".$ctipd_header."Spam: $spam_result, ".$this->{pos_text}. ")");
      }
      $message->{prefilterreport} .= ", ".blessed($this)." ($ctipd_header Spam: $spam_result, ".$this->{pos_text}. ")";
      return 1;
    }

    if ($vod_result eq 'Virus' ||
        ($vod_result eq 'High' && $this->{'detect_vod_high'}) ||
        ($vod_result eq 'Medium' && $this->{'detect_vod_medium'}) )
    {
      MailScanner::Log::InfoLog(blessed($this)." result is spam (".$ctipd_header."VOD: $vod_result) for ".$message->{id});
      if ($this->{'putSpamHeader'}) {
        $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is spam (".$ctipd_header."VOD: $vod_result, ".$this->{pos_text}. ")");
      }
      $message->{prefilterreport} .= ", ".blessed($this)." ($ctipd_header VOD: $vod_result, ".$this->{pos_text}. ")";

      return 1;
    }

    MailScanner::Log::InfoLog(blessed($this)." result is not spam (".$ctipd_header."Spam: $spam_result, VOD: $vod_result) for ".$message->{id});
    if ($this->{'putHamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $this->{'header'}, "is not spam (".$ctipd_header."Spam: $spam_result, VOD: $vod_result," .$this->{'neg_text'}. ")");
    }
    $message->{prefilterreport} .= ", ".blessed($this)." ($ctipd_header VOD: $vod_result, " .$this->{'neg_text'}. ")";
  }
  return 0;
}

sub dispose($this) {
  MailScanner::Log::InfoLog(blessed($this)." module disposing...");
  return;
}

1;
