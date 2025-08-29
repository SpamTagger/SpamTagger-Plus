#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2022 John Mertz <git@john.me.tz>
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
#
#   Library to decode URLs from URL scanning and Rewriting services.

package URLRedirects;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use URI::Escape;

sub new ($class = "URLRedirects", $args = {}) {
  my $this = $args;
  $this->{'services'} = get_services();
  $this->{'generics'} = get_generics();
  # Prioritize specific services over generic patterns. Split with 'undef' to indicate when search hash has changed
  $this->{'all'} = [ keys(%{$this->{'services'}}), undef, keys(%{$this->{'generics'}}) ];
  return bless $this, $class;
}

sub get_services {
  # List of known rewriting services. Each requires a 'regex' for the URL input
  # pattern and a 'decoder' function which returns the decoded URL.
  my %services = (
    "Bing" => {
      "regex" => qr%bing\.com/ck/a\?!&&%,
      "decoder" => sub {
        my $url = shift;
        $url =~ s%.*bing\.com/ck/a\?!&&(?:[^u=]+=[^&]+&)*u=a1([^&]+)&.*%$1%;
        return decode_base64($url);
      }
    },
    "LinkedIn" => {
      "regex" => qr%linkedin.com/slink\?code=([^#]+)%,
      "decoder" => sub {
        return head(shift);
      }
    },
    "Proofpoint-v2" => {
      "regex"   => qr#urldefense\.proofpoint\.com/v2#,
      "decoder" => sub {
        my $url = shift;
        $url =~ s|\-|\%|g;
        $url =~ s|_|\/|g;
        $url = uri_unescape($url);
        $url =~ s/^[^\?]*\?u=([^&]*)&.*$/$1/;
        return $url;
      }
    },
    "Proofpoint-v3" => {
      "regex"   => qr#urldefense\.com/v3#,
      "decoder" => sub {
        my $url = shift;
        $url =~ s|[^_]*__(.*)/__.*|$1|;
        $url = uri_unescape($url);
        $url =~ s/^[^\?]*\?u=([^&]*)&.*$/$1/;
        return $url;
      }
    },
    "Roaring Penguin" => {
      "regex"   => qr#[^/]*/canit/urlproxy.php\?_q=[a-zA-Z0-9]+#,
      "decoder" => sub {
        use MIME::Base64;
        my $url = shift;
        $url =~ s|[^/]*/canit/urlproxy\.php\?_q\=([^&]*).*|$1|;
        $url = uri_unescape($url) ;
        return decode_base64($url);
      }
    },
  );
  return \%services;
}

sub get_generics {
  # Fallback patterns to be checked if no specific service is matched
  my %generics = (
    # Generic uri_encoded path included as a url argument
    "uri_encoded_arg" => {
      "regex"   => qr#^[^/]*/[^\?]*\?.*=https?\%3A\%2F\%2F#,
      "decoder" => sub {
        my $url = shift;
        $url =~ s#^[^/]*/[^\?]*\?.*=https?\%3A\%2F\%2F([^&]*)&?.*#$1#;
        return uri_unescape($url);
      }
    }
  );
  return \%generics;
}

# The actual simple search and decode function
sub decode ($this, $url, $recursed = 0) {
  $url =~ s#^https?://##;
  my $type = 'services';
  foreach my $service (@{$this->{'all'}}) {
    if (!defined($service)) {
      $type = 'generics';
      next;
    }
    if ($url =~ $this->{$type}->{$service}->{'regex'}) {
      my $decoded = $this->{$type}->{$service}->{'decoder'}($url);
      if ($decoded) {
        # Limit recursion to 10 steps
        return $decoded if ($recursed == 10);
        return $this->decode($decoded, ++$recursed);
      } else {
        return $url if ($recursed);
        return 0;
      }
    }
  }
  return $url if ($recursed);
  return 0;
}

sub head ($url) {
  use LWP::UserAgent;
  my $ua = LWP::UserAgent->new();
  $ua->max_redirect(0);

  my $head = $ua->head($url);
  return unless ($head->{_rc} == 301);
  return $head->{_headers}->{location};
}

1;
