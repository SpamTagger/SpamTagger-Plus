#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2021 John Mertz <git@john.me.tz>
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
#   This script will output the count of messages/spams/viruses for a domain/user or globaly for a given period

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use GetDNS();

sub usage {
  print "\nUsage: $0 [a|aaaa|mx|spf] domain <ip>\n
    a       query A record
    aaaa    query AAAA record
    mx      query MX record
    spf     query SPF record
    domain  the domain to query
    ip      (optional) check if given IP is in the list of results
  \n";
  exit();
}

usage unless (defined($ARGV[1]) && $ARGV[0] =~ m/^(a|aaaa|mx|spf)$/i);

my $dns = GetDNS->new();

my ($target,$v);
if (defined $ARGV[2]) {
  $target = $ARGV[2];
  unless ( $dns->{'validator'}->is_ipv4($ARGV[2])
    || $dns->{'validator'}->is_ipv6($ARGV[2]) )
  {
    print "\n'$target' is not a IPv4 or IPv6 address\n";
    usage();
  }
}

my @ips;
if ($ARGV[0] eq 'a' || $ARGV[0] eq 'A') {
  @ips = $dns->get_a($ARGV[1]);
} elsif ($ARGV[0] eq 'aaaa' || $ARGV[0] eq 'AAAA') {
  @ips = $dns->get_aaaa($ARGV[1]);
} elsif ($ARGV[0] eq 'mx' || $ARGV[0] eq 'MX') {
  @ips = $dns->get_mx($ARGV[1]);
} elsif ($ARGV[0] eq 'spf' || $ARGV[0] eq 'SPF') {
  @ips = $dns->get_spf($ARGV[1]);
} else {
  die "Invalid record type\n";
}

if ($target) {
  print $dns->in_ip_list($target,@ips) . "\n";
} else {
  print("$_\n") foreach (@ips);
}
