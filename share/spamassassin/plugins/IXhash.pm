=head1 NAME
Mail::SpamAssassin::Plugin::IXhash - compute fuzzy checksums from mail bodies and compare to known spam ones via DNS
=head1 SYNOPSIS
loadplugin    Mail::SpamAssassin::Plugin::IXhash /path/to/IXhash.pm
# Timeout in seconds - default is 10 seconds
ixhash_timeout      10

# Should we add the hashes to the messages' metadata for later re-use
# Default is not to cache hashes (i.e. re-compute them for every check)
use_ixhash_cache    0

# wether to only use perl (ixhash_pureperl = 1) or the system's 'tr' and 'md5sum'
# Default is to use Perl only
ixhash_pureperl      1

# If you should have 'tr' and/or 'md5sum' in some weird place (e.g on a Windows server)
# or you want to specify which version to use you can specifiy the exact paths here
# Default is to have SpamAssassin find the executables
ixhash_tr_path          "/usr/bin/tr"
ixhash_md5sum_path      "/usr/bin/md5sum"

# The actual rule
body          IXHASH eval:ixhashtest('ix.dnsbl.manitu.net')
describe      IXHASH This mail has been classified as spam @ iX Magazine, Germany
tflags        IXHASH net
score         IXHASH 1.5


=head1 DESCRIPTION

IXhash.pm is a plugin for SpamAssassin 3.0.0 and up. It takes the body of a mail, strips parts from it and then computes a hash value
from the rest. These values will then be looked up via DNS to see if the hashes have already been categorized as spam by others.
This plugin is based on parts of the procmail-based project 'NiX Spam', developed by Bert Ungerer.(un@ix.de)
For more information see http://www.heise.de/ix/nixspam/. The procmail code producing the hashes only can be found here:
ftp://ftp.ix.de/pub/ix/ix_listings/2004/05/checksums

To see which DNS zones are currently available see http://www.ixhash.net


=cut

package Mail::SpamAssassin::Plugin::IXhash; ## no critic

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
my $VERSION = "1.5.5";

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;

use Digest::MD5 qw(md5 md5_hex md5_base64);
use Net::DNS;

use parent qw(Mail::SpamAssassin::Plugin);

sub new ($class, $mailsa, $server) {
  $class = ref($class) || $class;
  my $this = $class->SUPER::new($mailsa);
  bless ($this, $class);
  # Are network tests enabled?
  if ($mailsa->{local_tests_only}) {
    dbg("IXHASH: local tests only, not using iXhash plugin");
    $this->{ixhash_available} = 0;
  } else {
    dbg("IXHASH: Using iXhash plugin $VERSION");
    $this->{ixhash_available} = 1;
  }

  $this->set_config($mailsa->{conf});
  $this->register_eval_rule ("ixhashtest");
  return $this;
}

sub set_config ($this, $conf) {
  my @cmds = ();
  # implements iXhash_timeout config option - by dallase@uribl.com
  push(@cmds, {
    setting => 'ixhash_timeout',
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    }
  );
  push(@cmds, {
    setting => 'use_ixhash_cache',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    }
  );
  push(@cmds, {
    setting => 'ixhash_pureperl',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    }
  );
  push(@cmds, {
    setting => 'ixhash_tr_path',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'ixhash_md5sum_path',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  $conf->{parser}->register_commands(\@cmds);
  return;
}

sub ixhashtest ($this, $permsgstatus,$full,$dnszone) {
  dbg("IXHASH: IxHash querying $dnszone");
  if ($permsgstatus->{main}->{conf}->{'ixhash_pureperl'} == 0){
    # Return subito if we are do not find the tools we need
    # Only relevant if we are those tools in the 1st way
    return 0 unless $this->is_md5sum_available();
    return 0 unless $this->is_tr_available();
  }
  my ($answer,$ixdigest) = "";
  # Changed to use get_pristine_body returning a scalar
  my $body = $permsgstatus->{msg}->get_pristine_body();
  my $resolver = Net::DNS::Resolver->new;
  my $body_copy = "";
  my $rr;
  my $tmpfile = '';
  my $tmpfh = undef;
  my $hits = 0;
  # alarm the dns query - dallase@uribl.com
  # --------------------------------------------------------------------------
  # here we implement proper alarms, ala Pyzor, Razor2 plugins.
  # keep the alarm as $oldalarm, so we dont lose the timeout-child alarm
  # see http://issues.apache.org/SpamAssassin/show_bug.cgi?id=3828#c123
  my $oldalarm = 0;
  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $permsgstatus->{main}->{conf}->{'ixhash_timeout'}});

  my $time_err = $timer->run_and_catch(sub {
    # create a temporary file unless we are to use only Perl code and we don't find a hash value in metadata
    # If we use the system's 'tr' and 'md5sum' utilities we need this.
    if ($permsgstatus->{main}->{conf}->{'ixhash_pureperl'} == 0){
      unless ($permsgstatus->{msg}->get_metadata('X-iXhash-hash-1') or $permsgstatus->{msg}->get_metadata('X-iXhash-hash-2') or $permsgstatus->{msg}->get_metadata('X-iXhash-hash-3')) {
        ($tmpfile, $tmpfh) = Mail::SpamAssassin::Util::secure_tmpfile();
        $body_copy = $body;
        $body_copy =~ s/\r\n/\n/g;
        print $tmpfh $body_copy;
        close $tmpfh;
        dbg ("IXHASH: Writing body to temporary file $tmpfile");
      } else {
        dbg ("IXHASH: Not writing body to temporary file - reusing stored hashes");
      }
    }

    my $digest = compute1sthash($permsgstatus, $body, $tmpfile);
    if ($digest){
      dbg ("IXHASH: Now checking $digest.$dnszone");
      # Now check via DNS query
      $answer = $resolver->query($digest.'.'.$dnszone, "A", "IN");
      if ($answer) {
        foreach my $rr ($answer->answer) {
          next unless $rr->type eq "A";
          dbg ("IXHASH: Received reply from $dnszone:". $rr->address);
          $hits = 1 if $rr->address =~ /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
        }
      }
    }
    # Only go ahead if $hits ist still 0 - i.e hash #1 didn't score a hit
    if ($hits == 0) {
      $digest = compute2ndhash($permsgstatus,$body, $tmpfile);
      if ($digest){
        dbg ("IXHASH: Now checking $digest.$dnszone");
        # Now check via DNS query
        $answer = $resolver->query($digest.'.'.$dnszone, "A", "IN");
        if ($answer) {
          foreach my $rr ($answer->answer) {
            next unless $rr->type eq "A";
            dbg ("IXHASH: Received reply from $dnszone:". $rr->address);
            $hits = 1 if $rr->address =~ /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
          } # end foreach
        } # end if $answer
      } # end if $digest
    } # end if $hits

    if ($hits == 0) {
      $digest = compute3rdhash($permsgstatus, $body, $tmpfile);
      if (length($digest) == 32){
        dbg ("IXHASH: Now checking $digest.$dnszone");
        # Now check via DNS query
        $answer = $resolver->query($digest.'.'.$dnszone, "A", "IN");
        if ($answer) {
          foreach my $rr ($answer->answer) {
            next unless $rr->type eq "A";
            dbg ("IXHASH: Received reply from $dnszone:". $rr->address);
            $hits = 1 if $rr->address =~ /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
          } # foreach $answer
        } # end if $anser
      } # end if $digest
    } # end if $hits
  }); # end of timer->run_and_catch

  if ($timer->timed_out()) {
    dbg("IXHASH: ".$permsgstatus->{main}->{conf}->{'ixhash_timeout'}." second timeout exceeded while checking $dnszone!");
  } elsif ($time_err) {
    chomp $time_err;
    dbg("IXHASH: iXhash lookup failed: $time_err");
  }
  unlink $tmpfile;
  return $hits;
}

sub compute1sthash ($permsgstatus, $body, $tmpfile) {
  my $body_copy = '';
  my $digest = '';
  if (($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1 ) && ($permsgstatus->{msg}->get_metadata('X-iXhash-hash-1'))) {
    dbg ("IXHASH: Hash value for method #1 found in metadata, re-using that one");
    $digest = $permsgstatus->{msg}->get_metadata('X-iXhash-hash-1');
  } else {
    if (($body =~ /(?>\s.+?){20}/g) || ( $body =~ /\n.*\n/ ) ){
      if ($permsgstatus->{main}->{conf}->{'ixhash_pureperl'} == 1 ){
        $body_copy = $body;
        $body_copy =~ s/\r\n/\n/g;
        # Step One
        $body_copy =~ s/([[:space:]]{100})(?:\1+)/$1/g;
        # Step Two
        $body_copy =~ s/([[:space:]])(?:\1+)/$1/g;
        # remove graph class chars and some specials
        $body_copy =~ s/[[:graph:]]+//go;
        # Create actual digest
        $digest = md5_hex($body_copy);
        dbg ("IXHASH: Computed hash-value ".$digest." via method 1, using perl exclusively");
        $permsgstatus->{msg}->put_metadata('X-iXhash-hash-1', $digest) if ($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) ;
      } else {
        $digest = `cat $tmpfile |  $permsgstatus->{main}->{conf}->{ixhash_tr_path} -s '[:space:]' | $permsgstatus->{main}->{conf}->{ixhash_tr_path} -d '[:graph:]' | $permsgstatus->{main}->{conf}->{ixhash_md5sum_path} |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  -d ' -'`;
        chop($digest);
        dbg ("IXHASH: Computed hash-value ".$digest." via method 1, using system utilities");
        $permsgstatus->{msg}->put_metadata('X-iXhash-hash-1', $digest) if ($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) ;
      }
    } else {
      dbg ("IXHASH: Hash value #1 not computed, requirements not met");
    }
  }
  return $digest;
}

sub compute2ndhash ($permsgstatus, $body, $tmpfile) {
  my $body_copy = '';
  my $digest = '';
  #  See if this hash has been computed already
  if (($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) && ($permsgstatus->{msg}->get_metadata('X-iXhash-hash-2'))) {
    dbg ("IXHASH: Hash value for method #2 found in metadata, re-using that one");
    $digest = $permsgstatus->{msg}->get_metadata('X-iXhash-hash-2');
  } else {
    # Creation of hash # 2 if mail contains at least 3 of the following characters:
    # '[<>()|@*'!?,]' or the combination of ':/'
    # (To match something like "Already seen?  http:/host.domain.tld/")
    if ($body =~ /((([<>\(\)\|@\*'!?,])|(:\/)).*?){3,}/m ) {
      if ($permsgstatus->{main}->{conf}->{'ixhash_pureperl'} == 1 ){
        $body_copy = $body;
        # remove redundant stuff
        $body_copy =~ s/[[:cntrl:][:alnum:]%&#;=]+//g;
        # replace '_' with '.'
        $body_copy =~ tr/_/./;
        # replace duplicate chars. This too suffers from a bug in perl
        # so we do it in two steps
        # Step One
        $body_copy =~ s/([[:print:]]{100})(?:\1+)/$1/g;
        # Step Two
        $body_copy =~ s/([[:print:]])(?:\1+)/$1/g;
        # Computing hash...
        $digest = md5_hex($body_copy);
        dbg ("IXHASH: Computed hash-value $digest via method 2, using perl exclusively");
        $permsgstatus->{msg}->put_metadata('X-iXhash-hash-2', $digest) if ($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) ;
      } else {
        $digest = `cat $tmpfile |  $permsgstatus->{main}->{conf}->{ixhash_tr_path} -d '[:cntrl:][:alnum:]%&#;=' |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  '_' '.' |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  -s '[:print:]' |  $permsgstatus->{main}->{conf}->{ixhash_md5sum_path}  |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  -d ' -'`;
        chop($digest);
        dbg ("IXHASH: Computed hash-value ".$digest." via method 2, using system utilities");
        $permsgstatus->{msg}->put_metadata('X-iXhash-hash-2', $digest) if ($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) ;
      }
    } else {
      dbg ("IXHASH: Hash value #2 not computed, requirements not met");
    }
  }
  return $digest;
}

sub compute3rdhash ($permsgstatus, $body, $tmpfile ) {
  my $body_copy = '';
  my $digest = '';
  #  See if this hash has been computed already
  if (($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) && ($permsgstatus->{msg}->get_metadata('X-iXhash-hash-3'))) {
    dbg ("IXHASH: Hash value for method #3 found in metadata, re-using that one");
    $digest = $permsgstatus->{msg}->get_metadata('X-iXhash-hash-3');
  } else {
    # Compute hash # 3 if
    # - there are at least 8 non-space characters in the body and
    # - neither hash #1 nor hash #2 have been computed
    #  (which means $digest is still empty, in any case < 32)
    if (($body =~ /[\S]{8}/) && (length($digest) < 32)) {
      if ($permsgstatus->{main}->{conf}->{'ixhash_pureperl'} == 1){
        $body_copy = $body;
        $body_copy =~ s/[[:cntrl:][:space:]=]+//g;
        # replace duplicate chars. This too suffers from a bug in perl
        # so we do it in two steps
        # Step One
        $body_copy =~ s/([[:print:]]{100})(?:\1+)/$1/g;
        # Step Two
        $body_copy =~ s/([[:graph:]])(?:\1+)/$1/g;
        # Computing actual hash
        $digest = md5_hex($body_copy);
        dbg ("IXHASH: Computed hash-value $digest via method 3");
        $permsgstatus->{msg}->put_metadata('X-iXhash-hash-3', $digest) if ($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) ;
      } else {
        # shellcode
        $digest = `cat $tmpfile |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  -d '[:cntrl:][:space:]=' |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  -s '[:graph:]' |  $permsgstatus->{main}->{conf}->{ixhash_md5sum_path}  |  $permsgstatus->{main}->{conf}->{ixhash_tr_path}  -d ' -'`;
        chop($digest);
        dbg ("IXHASH: Computed hash-value ".$digest." via method 3, using system utilities");
        $permsgstatus->{msg}->put_metadata('X-iXhash-hash-3', $digest) if ($permsgstatus->{main}->{conf}->{'use_ixhash_cache'} == 1) ;
      }
    } else {
      dbg ("IXHASH: Hash value #3 not computed, requirements not met");
    }
  }
  return $digest;
}

sub is_tr_available ($this) {
  # Find out where your 'tr' lives
  # shamelessly stolen from the Pyzor plugin code
  my $tr = $this->{main}->{conf}->{ixhash_tr_path} || '';
  $tr = Mail::SpamAssassin::Util::find_executable_in_env_path('tr') unless ($tr);
  unless ($tr && -x $tr) {
    dbg("IXHASH: tr is not available: no tr executable found");
    return 0;
  }
  # remember any found tr
  $this->{main}->{conf}->{ixhash_tr_path} = $tr;
  dbg("IXHASH: tr is available: " . $this->{main}->{conf}->{ixhash_tr_path});
  return 1;
}

sub is_md5sum_available ($this) {
  # Find out where your 'md5sum' lives
  # again shamelessly stolen from the Pyzor plugin code
  my $md5sum = $this->{main}->{conf}->{ixhash_md5sum_path} || '';
  $md5sum = Mail::SpamAssassin::Util::find_executable_in_env_path('md5sum') unless ($md5sum);
  unless ($md5sum && -x $md5sum) {
    dbg("IXHASH: md5sum is not available: no md5sum executable found");
    return 0;
  }
  # remember any found md5sum
  $this->{main}->{conf}->{ixhash_md5sum_path} = $md5sum;
  dbg("IXHASH: md5sum is available: " . $this->{main}->{conf}->{ixhash_md5sum_path});
  return 1;
}

1;
