#!/usr/bin/env perl

package MailScanner::MessageSniffer;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use IO();
use POSIX qw(:signal_h); # For Solaris 9 SIG bug workaround
use IO::Socket();
use IO::File();
use File::Temp qw/ tempfile tempdir /;

my $MODULE = "MessageSniffer";
my %conf;

# translation table for SNF rule codes
my $rule_code_xlat = {
    0  => 'Standard White Rules',
    20 => 'GBUdb Truncate (superblack)',
    40 => 'GBUdb Caution (suspicious)',
    47 => 'Travel',
    48 => 'Insurance',
    49 => 'Antivirus Push',
    50 => 'Media Theft',
    51 => 'Spamware',
    52 => 'Snake Oil',
    53 => 'Scam Patterns',
    54 => 'Porn/Adult',
    55 => 'Malware & Scumware Greetings',
    56 => 'Ink & Toner',
    57 => 'Get Rich',
    58 => 'Debt & Credit',
    59 => 'Casinos & Gambling',
    60 => 'Ungrouped Black Rules',
    61 => 'Experimental Abstract',
    62 => 'Obfuscation Techniques',
    63 => 'Experimental Received [ip]',
};

sub initialise {
  MailScanner::Log::InfoLog("$MODULE module initializing...");

  my $confdir = MailScanner::Config::Value('prefilterconfigurations');
  my $configfile = $confdir."/$MODULE.cf";
  %MessageSniffer::conf = (
     header => "X-$MODULE",
     putHamHeader => 0,
     putSpamHeader => 1,
     putDetailedHeader => 1,
     scoreHeader => "X-$MODULE-result",
     maxSize => 0,
     timeOut => 20,
     SFNPort => 9001,
     SFNHost => 'localhost',
     SFNTimeout => 10,
     tmpDir => '/tmp/MessageSniffer',
     MaxTempFileSize => 64 * 1024,
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
       $MessageSniffer::conf{$1} = $2;
      }
    }
    close $CONFIG;
  } else {
    MailScanner::Log::WarnLog("$MODULE configuration file ($configfile) could not be found !");
  }

  if ($MessageSniffer::conf{'pos_decisive'} && ($MessageSniffer::conf{'decisive_field'} eq 'pos_decisive' || $MessageSniffer::conf{'decisive_field'} eq 'both')) {
    $MessageSniffer::conf{'pos_text'} = 'position : '.$MessageSniffer::conf{'position'}.', spam decisive';
  } else {
    $MessageSniffer::conf{'pos_text'} = 'position : '.$MessageSniffer::conf{'position'}.', not decisive';
  }
  if ($MessageSniffer::conf{'neg_decisive'} && ($MessageSniffer::conf{'decisive_field'} eq 'neg_decisive' || $MessageSniffer::conf{'decisive_field'} eq 'both')) {
    $MessageSniffer::conf{'neg_text'} = 'position : '.$MessageSniffer::conf{'position'}.', ham decisive';
  } else {
    $MessageSniffer::conf{'neg_text'} = 'position : '.$MessageSniffer::conf{'position'}.', not decisive';
  }
  return;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic

  ## check maximum message size
  my $maxsize = $MessageSniffer::conf{'maxSize'};
  if ($maxsize > 0 && $message->{size} > $maxsize) {
    MailScanner::Log::InfoLog("Message %s is too big for MessageSniffer checks (%d > %d bytes)",
                              $message->{id}, $message->{size}, $maxsize);
    $message->{prefilterreport} .= ", MessageSniffer (too big)";
    $global::MS->{mta}->AddHeaderToOriginal($message, $MessageSniffer::conf{'header'}, "too big (".$message->{size}." > $maxsize)");
    return 0;
  }

  my (@whole_message, $maxsize);
  push(@whole_message, $global::MS->{mta}->OriginalMsgHeaders($message, "\n"));
  push(@whole_message, "\n");
  $message->{store}->ReadBody(\@whole_message, 0);

  my $msgtext = "";
  foreach my $line (@whole_message) {
    $msgtext .= $line;
  }

  # Make sure we have a temp dir
  unless(-d $MessageSniffer::conf{'tmpDir'}) {
     mkdir($MessageSniffer::conf{'tmpDir'});
     chmod(o777, $MessageSniffer::conf{'tmpDir'});
  };

  my $tim = $MessageSniffer::conf{'timeOut'};
  use Mail::SpamAssassin::Timeout;
  my $t = Mail::SpamAssassin::Timeout->new({ secs => $tim });
  my $is_prespam = 0;
  my $ret = -5;
  my $snf_xci_return;
  my @lines;

  $t->run(sub {

    # Truncate the message.
    my $mailtext = substr( $msgtext, 0, $MessageSniffer::conf{'MaxTempFileSize'} );

    # create our temp file, $filename will contain the full path
    my ($fh, $filename) = tempfile( DIR => $MessageSniffer::conf{'tmpDir'} );

    # spew our mail into the temp file
    my $snf_fh = IO::File->new( $filename, "w" ) || $this->clean_die($filename, "Unable to create temporary file '" . $filename . "'");
    $snf_fh->print($mailtext) || $this->clean_die($filename, "Unable to write to temporary file '" .  $filename . "'");
    $snf_fh->close || $this->clean_die($filename, "Unable to close temporary file '" .  $filename . "'");

    # Change permissions.
    my $cnt = chmod(o666, $filename) || $this->clean_die($filename, "Unable to change permissions of temporary file '" .  $filename . "'");

    # xci_scan connects to SNFServer with XCI to scan the message
    $snf_xci_return = $this->xci_scan( $filename, $message->{clientip} );

    MailScanner::Log::DebugLog("$MODULE returned: succes = ".$snf_xci_return->{success}.", code = ".$snf_xci_return->{code}.", message = ".$snf_xci_return->{message});

    # Remove the temp file, we are done with it.
    unlink($filename);

  });
  if ($t->timed_out()) {
    MailScanner::Log::InfoLog("$MODULE timed out for ".$message->{id}."!");
    $global::MS->{mta}->AddHeaderToOriginal($message, $MessagSniffer::conf{'header'}, 'timeout');
    return 0;
  }
  ## not spam per default
  $ret = 1;
  my $spamfound = "";
## analyze result

  my $desc = $snf_xci_return->{code}.' - Unknown';
  #if (defined($rule_code_xlat{$snf_xci_return->{code}})) {
    $desc = $snf_xci_return->{code}.' - '.$rule_code_xlat->{$snf_xci_return->{code}};
  #}

  if ($snf_xci_return->{code} > 0) {
    ## is spam
    MailScanner::Log::InfoLog("$MODULE result is spam ($desc) for ".$message->{id});
    if ($MessageSniffer::conf{'putSpamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $MessageSniffer::conf{'header'}, "is spam ($desc, " .$MessageSniffer::conf{pos_text} .")");
    }
    $message->{prefilterreport} .= ", MessageSniffer ($desc, ".$MessageSniffer::conf{pos_text}.")";
    return 1;
  } elsif ($snf_xci_return->{code} == 0) {
    MailScanner::Log::InfoLog("$MODULE result is not spam ($desc) for ".$message->{id});
    if ($MessageSniffer::conf{'putHamHeader'}) {
      $global::MS->{mta}->AddHeaderToOriginal($message, $MessageSniffer::conf{'header'}, "is not spam ($desc, ".$MessageSniffer::conf{neg_text}. ")");
    }
    $message->{prefilterreport} .= ", MessageSniffer ($desc, ".$MessageSniffer::conf{neg_text}.")";
  }
  return 0;
}

sub dispose {
  MailScanner::Log::InfoLog("$MODULE module disposing...");
  return;
}


# xci_scan( $file , $ip)
# returns hashref:
#   success : true/false
#   code    : response code from SNF
#   message : scalar message (if any)
sub xci_scan ($this, $file, $ip ) {
    my $ret_hash = {
        success => undef,
        code    => undef,
        message => undef,
        header  => undef,
        xml     => undef
    };

    my $xci = $this->connect_socket( $MessageSniffer::conf{'SFNHost'}, $MessageSniffer::conf{'SFNPort'} )
      or return $this->err_hash("cannot connect to socket ($!)");

    if ($ip =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
        $xci->print("<snf><xci><scanner><scan file='$file' xhdr='yes' ip='$ip'/></scanner></xci></snf>\n");
    } else {
        $xci->print("<snf><xci><scanner><scan file='$file' xhdr='yes'/></scanner></xci></snf>\n");
    }
    my $rc = $ret_hash->{xml} = $this->socket_response($xci, $file);
    $xci->close;


    if ( $rc =~ /^<snf><xci><scanner><result code='(\d*)'>/ ) {
        $ret_hash->{success} = 1;
        $ret_hash->{code}    = $1;
        $rc =~ /<xhdr>(.*)<\/xhdr>/s and $ret_hash->{header} = $1;
    } elsif ( $rc =~ /^<snf><xci><error message='(.*)'/ ) {
        $ret_hash->{message} = $1;
    } else {
        $ret_hash->{message} = "unknown XCI response: $rc";
    }

    return $ret_hash;
}

# connect_socket( $host, $port )
# returns IO::Socket handle
sub connect_socket ($this, $host, $port) {
    my $protoname = 'tcp';    # Proto should default to tcp but it's not expensive to specify

    my $xci_socket = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => $protoname,
        Timeout  => $MessageSniffer::conf{'SFNTimeout'} ) or return;

    $xci_socket->autoflush(1);    # make sure autoflush is on -- legacy
    return $xci_socket;           # return the socket handle
}

# socket_response( $socket_handle )
# returns scalar string
sub socket_response ($this, $rs, $file) {
    my $buf = '';    # buffer for response
    # blocking timeout for servers who accept but don't answer
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };    # set up the interrupt
        alarm $MessageSniffer::conf{'SFNTimeout'};                    # set up the alarm
        while (<$rs>) {                                # read the socket
            $buf .= $_;
        }
        alarm 0;                                       # reset the alarm
    };

    # report a blocking timeout
    if ( $@ eq "timeout\n" ) {
        die('Timeout waiting for response from SNFServer');
    } elsif ( $@ =~ /alarm.*unimplemented/ ) {         # no signals on Win32
        while (<$rs>) {                                # get whatever's left
                                                       # in the socket.
            $buf .= $_;
        }
    }
    return $buf;
}

# return an error message for xci_scan
sub err_hash ($this, $message) {
    return {
        success => undef,
        code    => undef,
        message => $message
    };
}

sub clean_die ($this, $file, $message) {
   unlink($file);
   MailScanner::Log::InfoLog("$MODULE failed with error ".$message);
   exit(1);
}


1;
