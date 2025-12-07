#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
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

package STDnsLists;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use IO::Pipe();
use POSIX qw(:signal_h);    # For Solaris 9 SIG bug workaround
use Net::HTTP();
use Net::IP();
use URLRedirects();

my %rblsfailure;
my %shorteners;

sub new ($class, $logfunction = sub { print STDERR shift."\n"; }, $debug = 0) {
  my $this        = {};

  $this->{rbls}                      = {};
  $this->{useable_rbls}               = ();
  $this->{wantlisted_domains}        = {};
  $this->{tlds}                      = {};
  $this->{local_domains}              = {};
  $this->{maxurilength}              = 150;
  $this->{logfunction}               = $logfunction;
  $this->{debug}                     = $debug;
  $this->{timeout}                   = 10;
  $this->{failuretobedead}           = 1;
  $this->{retrydeadinterval}         = 120;
  $this->{shortner_resolver_maxdeep} = 10;
  $this->{shortner_resolver_timeout} = 5;
  $this->{url_redirects}              = URLRedirects->new();

  %rblsfailure = ();

  bless $this, $class;
  return $this;
}

sub load_rbls
  (
    $this, $rblspath, $selected_rbls, $rbls_type,
    $wantlist_domains_file, $tlds_file, $local_domains_file, $prelog
  )
{
  my $DIR;
  if ( opendir($DIR, $rblspath ) ) {
    while ( my $entry = readdir($DIR) ) {
      if ( $entry =~ m/\S+\.cf$/ ) {
        my $rblname = '';
        my $RBLFILE;
        if ( open($RBLFILE, '<', $rblspath . "/" . $entry ) ) {
          while (<$RBLFILE>) {
            if (/^name\s*=\s*(\S+)$/) {
              $rblname                            = $1;
              $this->{rbls}{$rblname}             = ();
              $this->{rbls}{$rblname}{'subrbls'}  = ();
              $this->{rbls}{$rblname}{'callonip'} = 1;
            }
            next if ( $rblname eq '' );
            if (/dnsname\s*=\s*([a-zA-Z0-9._-]+)$/) {
              $this->{rbls}{$rblname}{'dnsname'} = $1.'.';
            }
            if (/type\s*=\s*([a-zA-Z0-9._-]+)$/) {
              $this->{rbls}{$rblname}{'type'} = $1;
            }
            if (/sublist\s*=\s*([^,]+),([a-zA-Z0-9._-]+),(.+)$/) {
              my $subrbl = {
                'mask' => $1,
                'id'   => $2,
                'info' => $3
              };
              push @{ $this->{rbls}{$rblname}{'subrbls'} },
                $subrbl;
            }
            if (/callonip\s*=\s*(0|false|no)/i) {
              $this->{rbls}{$rblname}{'callonip'} = 0;
            }
          }
          close $RBLFILE;
        }
      }
    }
    close $DIR;
    if ( $this->{debug} ) {
      &{ $this->{logfunction} }( "$prelog loaded " .
          keys( %{ $this->{rbls} } ) . " useable RBLs" );
    }
  } else {
    &{ $this->{logfunction} }("$prelog could not open RBL's definition directory ($rblspath)");
  }

  my %deadrbls = ();
  my @neededrbls = split( ' ', $selected_rbls );
  foreach my $r (@neededrbls) {
    if ( defined( $this->{rbls}{$r}{'dnsname'} ) ) {
      push @{ $this->{useable_rbls} }, $r;
    } else {
      &{ $this->{logfunction} }(
        "$prelog configured to use $r, but this RBLs is not available !"
      );
    }
  }
  if ( $this->{useable_rbls} ) {
    &{ $this->{logfunction} }( "$prelog using "
        . @{ $this->{useable_rbls} }
        . " RBLs ("
        . join( ', ', @{ $this->{useable_rbls} } )
        . ")" );
  } else {
    &{ $this->{logfunction} }("$prelog not using any RBLs");
  }

  ## loading wantlisted domains
  my $FILE;
  if ( open($FILE, '<', $wantlist_domains_file ) ) {
    while (<$FILE>) {
      if (/\s*([-_.a-zA-Z0-9]+)/) {
        $this->{wantlisted_domains}{$1} = 1;
      }
    }
    close $FILE;
    &{ $this->{logfunction} }( "$prelog loaded " .
        keys( %{ $this->{wantlisted_domains} } )
        . " wantlisted domains" );
  } elsif ( $wantlist_domains_file ne '' ) {
    &{ $this->{logfunction} }(
          "$prelog could not load domains wantlist file ("
        . $wantlist_domains_file
        . ") !" );
  }

  ## loading tlds
  foreach my $tldfile ( split( '\s', $tlds_file ) ) {
    if ( open($FILE, '<', $tldfile ) ) {
      while (<$FILE>) {
        if (/^([-_.a-zA-Z0-9]+)/i) {
          $this->{tlds}{ lc($1) } = 1;
        }
      }
      close $FILE;
    } elsif ( $tldfile ne '' ) {
      &{ $this->{logfunction} }(
            "$prelog could not load two levels tlds file (" . $tldfile
          . ") !" );
    }
  }
  if ( $tlds_file ne '' ) {
    &{ $this->{logfunction} }(
      "$prelog loaded " . keys( %{ $this->{tlds} } ) . " tlds" );
  }

  ## loading local domains
  if ( open($FILE, '<', $local_domains_file ) ) {
    while (<$FILE>) {
      if (/^(\S+):/) {
        $this->{local_domains}{$1} = 1;
      }
    }
    close $FILE;
    &{ $this->{logfunction} }( "$prelog loaded " .
      keys( %{ $this->{local_domains} } ) . " local domains" );
  }

  ## loading url shorteners
  my $shortfile = $rblspath . '/url_shorteners.txt';
  if ( open($FILE, '<', $shortfile ) ) {
    while (<$FILE>) {
      if (/^([a-z.\-]+)/i) {
        $this->{shorteners}{$1} = 1;
      }
    }
    close $FILE;
  }
  if ( keys( %{ $this->{shorteners} } ) ) {
    &{ $this->{logfunction} }( "$prelog loaded " .
      keys( %{ $this->{shorteners} } ) . " shorteners" );
  }
  return;
}

sub find_uri ($this, $line, $prelog) {
  if ( $line =~ m|(?:https?://)?([^#/" ><=\[\]()]{3,$this->{maxurilength}})| ) {
    my $authority = $1;
    $authority =~ s/\n//g;
    $authority = lc($authority);
    my $u = $authority;

    ## avoid some easy fooling
    $u =~ s/[*,=]//g;
    $u =~ s/=2E/./g;

    return $this->is_valid_domain( $u, 1, $prelog );
  }
  return 0;
}

sub find_uri_shortener ($this, $line, $prelog) {
  my $deep           = 0;
  my $newloc         = $line;
  my $continue       = 1;
  my $final_location = 0;
  my $first_link     = '';
  while ( $deep++ <= $this->{shortner_resolver_maxdeep} ) {
    my ( $link, $nl ) = $this->get_next_location($newloc);
    last unless ($nl);
    $first_link = $link if ( $first_link eq '' );
    $newloc         = $nl;
    $final_location = $newloc;
  }
  $final_location =~ s/([%?].*)//g;
  if ( $final_location =~ m|bit\.ly/a/warning| ) {
    &{ $this->{logfunction} }(
      "$prelog found urlshortener with disabled link: $first_link");
    return 'disabled-link-bit.ly';
  }
  my $final_domain = $this->find_uri( $final_location, $prelog );
  if ( $deep > 1 ) {
    &{ $this->{logfunction} }(
"$prelog found urlshortener/redirect to $final_location"
    );
  }
  if ( $deep >= $this->{shortner_resolver_maxdeep} ) {
    &{ $this->{logfunction} }(
          "$prelog urlshortner finder reached max depth ("
        . $deep
        . ")" );
  }
  return $final_domain;
}

sub get_next_location ($this, $uri) {
  my ($domain, $get) = $uri =~ m#(?:(?:(?^:https?))://((?:(?:(?:(?:(?:[a-zA-Z0-9][-a-zA-Z0-9]*)?[a-zA-Z0-9])[.])*(?:[a-zA-Z][-a-zA-Z0-9]*[a-zA-Z0-9]|[a-zA-Z])[.]?)|(?:[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+)))(?::(?:(?:[0-9]*)))?(?:/(((?:(?:(?:(?:[a-zA-Z0-9\-_.!~*'():@&=+$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\-_.!~*'():@&=+$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*)(?:/(?:(?:(?:[a-zA-Z0-9\-_.!~*'():@&=+$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)(?:;(?:(?:[a-zA-Z0-9\-_.!~*'():@&=+$,]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*))*))*))(?:[?](?:(?:(?:[;/?:@&=+$,a-zA-Z0-9\-_.!~*'()]+|(?:%[a-fA-F0-9][a-fA-F0-9]))*)))?))?)#mg;
  unless (defined($domain)) {
    return ( $uri, 0 );
  }
  $domain = lc($domain);
  $domain =~ s/[*,=]//g;
  $domain =~ s/=2E/./g;

  # Test Redirect (when it contains a URL query)
  if ( defined($get) && ($get =~ m/\?([a-zA-Z0-9\$\-_\.\+!\*'\(\),\/\?&]+)=/) ) {
    if ( defined($shorteners{$domain.'/'.$get}) ) {
      return $shorteners{$domain.'/'.$get};
    }
    my $redirect = $this->{url_redirects}->decode($domain.'/'.$get);
    if ($redirect) {
      $shorteners{$domain.'/'.$get} = $redirect;
      return ( $domain.'/'.$get , $redirect );
    } else {
      return ( '' , 0 );
    }

  # Test shortener (no query, but simple GET path)
  } elsif ( defined($get) && $get =~ m|^[a-zA-Z0-9]{5,}$| ) {
    my $request = $domain.'/'.$get;

    if ( defined( $shorteners{$request} ) ) {
      return $shorteners{$request};
    }
    if ( !defined( $this->{shorteners}{$domain} ) ) {
      return ( '', 0 );
    }

    my $s = Net::HTTP->new(
      Host    => $domain,
      Timeout => $this->{shortner_resolver_timeout}
    );
    if ($s) {
      $s->write_request(
        GET          => "/" . $get,
        'User-Agent' => "Mozilla/5.0"
      );
      my ( $code, $mess, %h );
      my $ret = eval {
        ( $code, $mess, %h ) = $s->read_response_headers( laxed => 1 );
      };
      if ( $code >= 300 && $code < 400 ) {
        if ( defined( $h{'Location'} ) ) {
          my $new_location = $h{'Location'};
          $shorteners{$request} = $new_location;
          return ( $request, $new_location );
        }
      }
      $shorteners{$request} = 0;
    }
    return ( $request, 0 );
  }
  return ( '', 0 );
}

sub find_email ($this, $line, $prelog) {
  return 0 unless $line;
  if ( my ( $local, $domain ) =
    $line =~
m/([a-zA-Z0-9-_.]{4,25})[ |[(*'"]{0,5}@[ |\])*'"]{0,5}([a-zA-Z0-9-_\.]{4,25}\.[ |[(*'"]{0,5}[a-z]{2,3})/
    )
  {
    my $add = $1 . "@" . $2;
    my $dom = $2;

    $add =~ s/^3D//;
    $add = lc($add);
    if ( !defined( $this->{local_domains}{$dom} )
      && $this->is_valid_domain( $dom, 0, $prelog ) )
    {
      return $add;
    }
  }
  return 0;
}

sub is_valid_domain ($this, $domain, $usewantlist, $prelog) {
  $domain =~ s/\%//g;

  if ( $domain =~ m/[a-z0-9\-_.:]+[.:][a-z0-9]{2,15}$/ ) {
    if ($usewantlist) {
      foreach my $wd ( keys %{ $this->{wantlisted_domains} } ) {
        if ( $domain =~ m/([^.]{0,150}\.$wd)$/ || $domain eq $wd ) {
          if ( $this->{debug} ) {
            &{ $this->{logfunction} }( $prelog
                . " has found wantlisted domain: $domain" );
          }
          return 0;
        }
      }
    }

    if ( $domain =~ m/^(\d+\.\d+\.\d+\.\d+|[a-f0-9:]+)$/ ) {
      if ( $this->{debug} ) {
        &{ $this->{logfunction} }(
          $prelog . " has found literal IP domain: $domain" );
      }
      return $domain;
    }

    foreach my $ld ( keys %{ $this->{local_domains} } ) {
      next if ( $ld =~ m/\*$/ );
      if ( $domain =~ m/([^.]{0,150}\.$ld)$/ || $domain eq $ld ) {
        if ( $this->{debug} ) {
          &{ $this->{logfunction} }(
            $prelog . " has found a local domain: $ld ($domain)" );
        }
        return 0;
      }
    }

    foreach my $tld ( keys %{ $this->{tlds} } ) {
      if ( $domain =~ m/([^.]{0,150}\.$tld)$/ ) {
        my $ret = $1;
        if ( $this->{debug} ) {
          &{ $this->{logfunction} }(
            $prelog . " has found a valid domain: $ret" );
        }
        return $ret;
      }
    }
  }
  if ( $this->{debug} ) {
    &{ $this->{logfunction} }(
      $prelog . " has found an invalid domain: '$domain'" );
  }
  return 0;
}

sub check_dns ($this, $value, $type, $prelog, $maxhitcount = 0, $maxbshitcount = 1) {
  if ( $this->{debug} ) {
    &{ $this->{logfunction} }( $prelog . " will check value: $value" );
  }

  my ( @hit_list, $checked, $hit_or_miss );

  my $pipe = IO::Pipe->new();
  if ( !$pipe ) {
    &{ $this->{logfunction} }(
'Failed to create pipe, %s, try reducing the maximum number of unscanned messages per batch',
      $!
    );
    return 0;
  }

  my $pipe_return = 0;
  my $pid = fork();
  die "Can't fork: $!" unless defined($pid);

  if ( $pid == 0 ) {

    # In the child
    my $is_spam = 0;
    my $rbl_entry;
    $pipe->writer();
    POSIX::setsid();
    $pipe->autoflush();

    my $hitcount   = 0;
    my $bshitcount = 0;

    foreach my $r ( @{ $this->{useable_rbls} } ) {
      if (   defined( $rblsfailure{$r}{'disabled'} )
        && $rblsfailure{$r}{'disabled'}
        && defined( $rblsfailure{$r}{'lastfailure'} ) )
      {
        if (
          time - $rblsfailure{$r}{'lastfailure'} >=
          $this->{'retrydeadinterval'} )
        {
          &{ $this->{logfunction} }( $prelog
              . " list $r disabled time exceeded, rehabilitating this RBL."
          );
          $rblsfailure{$r}{'disabled'} = 0;
        }
        else {
          if ( $this->{debug} ) {
            &{ $this->{logfunction} }(
              $prelog . " list $r disabled." );
          }
          next;
        }
      }
      next if ( !defined( $this->{rbls}{$r}{'dnsname'} ) );
      next
        if ( !defined( $this->{rbls}{$r}{'type'} )
        || $this->{rbls}{$r}{'type'} ne $type );
      last if ( $maxhitcount   && $hitcount >= $maxhitcount );
      last if ( $maxbshitcount && $bshitcount >= $maxbshitcount );

      my $callvalue = $value;
      if ($callvalue =~ m/^(\d+\.\d+\.\d+\.\d+|[a-f0-9\:]{5,71})$/) {
        if ($this->{rbls}{$r}{'type'} =~ m/^URIRBL$/i && $this->{rbls}{$r}{'callonip'} == 0) {
          if ( $this->{debug} ) {
            &{ $this->{logfunction} }( $prelog . " not checking literal IP ".$callvalue." against ".$this->{rbls}{$r}{'dnsname'}." ( callonip = ".$this->{rbls}{$r}{'callonip'}." )" );
          }
          next;
        }
        my $ip_object = Net::IP->new($callvalue);
        if ($ip_object) {
          $callvalue = $ip_object->reverse_ip;
          $callvalue =~ s/[a-z0-9]\.arpa\.$//;
          $callvalue =~ s/\.in-add$//;
          $callvalue =~ s/\.ip$//;
          $callvalue =~ s/\.\./\./;
        }
      }

      if ( $this->{debug} ) {
        &{ $this->{logfunction} }( $prelog
            . " checking '$callvalue' against "
            . $this->{rbls}{$r}{'dnsname'} );
      }

      $rbl_entry =
        gethostbyname( "$callvalue." . $this->{rbls}{$r}{'dnsname'} );
      if ($rbl_entry) {
        $rbl_entry = Socket::inet_ntoa($rbl_entry);
        if ( $rbl_entry =~ /^127\.[01]\.[0-9]\.[0123456789]\d*$/ ) {
          # Got a hit!
          # now check with sublists masks
          my $subhit = 0;
          foreach my $sub ( @{ $this->{rbls}{$r}{'subrbls'} } ) {
            my $reg = $sub->{'mask'};
            if ( $rbl_entry =~ m/$reg/ ) {
              print $pipe $r . "\n";
              $is_spam = 1;
              print $pipe "Hit $rbl_entry\n";
              if ( $this->{rbls}{$r}{'type'} eq 'BSRBL' ) {
                $bshitcount++;
              }
              else {
                $hitcount++;
              }
            }
            else {
              print $pipe $r . "\n";
              print $pipe "Miss\n";
            }
          }
          print $pipe $r . "\n";
          print $pipe "Miss\n";
        }
        else {
          print $pipe $r . "\n";
          print $pipe "Miss\n";
        }
      }
      else {
        print $pipe $r . "\n";
        print $pipe "Miss\n";
      }
    }
    $pipe->close();
    exit $is_spam;
  }

  my $ret = eval {
    $pipe->reader();
    local $SIG{ALRM} = sub { die "Command Timed Out" };
    alarm $this->{'timeout'};

    while (<$pipe>) {
      chomp;
      $checked = $_;
      $hit_or_miss = <$pipe>;
      chomp $hit_or_miss;
      if ($hit_or_miss =~ m/Hit (127\.\d+\.\d+\.\d+)/) {
        push @hit_list, $checked;
        &{ $this->{logfunction} }(
                                        $prelog . " $value $checked => $hit_or_miss" );
      }
    }
    $pipe->close();
    waitpid $pid, 0;
    # This is not used...
    $pipe_return = $?;
    alarm 0;
    $pid = 0;
  };
  alarm 0;

  # Workaround for bug in perl shipped with Solaris 9,
  # it doesn't unblock the SIGALRM after handling it.
  #eval {
  #  my $unblockset = POSIX::SigSet->new(SIGALRM);
  #  sigprocmask(SIG_UNBLOCK, $unblockset)
  #    or die "Could not unblock alarm: $!\n";
  #};

  # Catch failures other than the alarm
  if ( $@ and $@ !~ /Command Timed Out/ ) {
    &{ $this->{logfunction} }(
      $prelog . " Checks failed with real error: $@" );
    die();
  }

  # In which case any failures must be the alarm
  if ( $pid > 0 ) {
    &{ $this->{logfunction} }(
      $prelog . " Check $checked timed out and was killed" );
    $rblsfailure{$checked}{'lastfailure'} = time;
    if ( defined( $rblsfailure{$checked}{'failures'} ) ) {
      $rblsfailure{$checked}{'failures'}++;
    }
    else {
      $rblsfailure{$checked}{'failures'} = 1;
    }
    if ( $rblsfailure{$checked}{'failures'} >= $this->{'failuretobedead'} )
    {
      $rblsfailure{$checked}{'disabled'} = 1;
      &{ $this->{logfunction} }( $prelog
          . " disabling $checked, not answering ! will retry in "
          . $this->{'retrydeadinterval'}
          . " seconds." );
    }

    # Kill the running child process
    my ($i);
    kill -15, $pid;
    for ( $i = 0 ; $i < 5 ; $i++ ) {
      sleep 1;
      waitpid( $pid, &POSIX::WNOHANG() );
      last unless kill( 0, $pid );
      kill -15, $pid;
    }

    # And if it didn't respond to 11 nice kills, we kill -9 it
    if ($pid) {
      kill -9, $pid;
      waitpid $pid, 0;    # 2.53
    }
  }

  my $temp = @hit_list;
  $temp = $temp + 0;
  $temp = 0 if ( !$hit_list[0] || $hit_list[0] !~ /[a-z]/i);
  return ( $value, $temp, join( ',', @hit_list ) );
}

sub get_all_rbls ($this) {
  return $this->{rbls};
}

sub get_useable_rbls ($this) {
  return $this->{useable_rbls};
}

sub get_debug_value ($this) {
  return $this->{debug};
}

1;
