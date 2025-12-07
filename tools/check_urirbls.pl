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

use v5.40;
use warnings;
use utf8;

use lib "/usr/spamtagger/lib/";
use STDnsLists();
use MIME::QuotedPrint();
use DB();
use ReadConfig();
use IO::Interactive();

my $conf = ReadConfig::get_instance();
our $SRCDIR = $conf->get_option('SRCDIR');

# Necessary configuration items
my $config = {
  'rbls' => '',
  'rblsDefsPath' => '',
  'whitelistDomainsFile' => '',
  'TLDsFiles' => '',
  'localDomainsFile' => ''
};

# Get values from file
my $configfile = "$SRCDIR/etc/mailscanner/prefilters/UriRBLs.cf";
my $CONFIG;
if (open($CONFIG, '<', $configfile)) {
  while (<$CONFIG>) {
    if (/^(\S+)\s*\=\s*(.*)$/) {
      if (defined($config->{$1})) {
        $config->{$1} = $2;
      }
    }
  }
  close $CONFIG;
} else {
  die("configuration file ($configfile) could not be found !");
}

# SMTP settings
my $db = DB->db_connect('replica', 'st_config');
my %mta_row = $db->get_hash_row("SELECT rbls FROM mta_config WHERE stage=1");
die "Failed to fetch SMTP config\n" unless %mta_row;

my %uri_row = $db->get_hash_row("SELECT rbls FROM UriRBLs");
die "Failed to fetch UriRBLs config\n" unless %uri_row;

my %spamc_row = $db->get_hash_row("SELECT sa_rbls FROM antispam");
die "Failed to fetch SpamC config\n" unless %spamc_row;

# Assemble RBL sources for each level of filtering
my %rbl_sources = (
  'SMTP'    => [ split(/\s+/, $mta_row{rbls}) ],
  'UriRBLs'  => [ split(/\s+/, $uri_row{rbls}) ],
  'SpamC'    => [ split(/\s+/, $spamc_row{sa_rbls}) ]
);

# Simplify hash with unique sources and the list of levels
my %rbl_levels = ();
foreach my $type (keys(%rbl_sources)) {
  foreach my $r (@{$rbl_sources{$type}}) {
    if (defined($rbl_levels{$r})) {
      $rbl_levels{$r} .= " $type";
    } else {
      $rbl_levels{$r} = "$type";
    }
  }
}

# Unique list of enabled sources
$config->{rbls} = join(' ', keys(%rbl_levels));

# Initialize lookup library
my $dnslists = STDnsLists->new(sub{ print STDERR "STDERR: " . shift . "\n"; });
$dnslists->load_rbls( $config->{rblsDefsPath}, $config->{rbls}, 'URIRBL', $config->{whitelistDomainsFile}, $config->{TLDsFiles}, $config->{localDomainsFile}, $0);

# Build input hash
my $current;
my %files;

# Load STDIN, if provided
unless (IO::Interactive::is_interactive()) {
  while (<STDIN>) {
    if (defined($files{'STDIN'})) {
      push(@{$files{'STDIN'}}, $_);
    } else {
      @{$files{'STDIN'}} = ( $_ );
    }
  }
}

# Load each file provided as an argument
foreach my $file (@ARGV) {
  my $authority = $files{$file}[0] =~ m|(?:(?:[^:/?#]+):)?(?://([^/?#]*))|;
  # If input object matches a URI, store it directly
  if (defined($authority)) {
    @{$files{$file}} = ( $authority );
    next;
  }
  # Otherwise treat the object as a file path
  my $fh;
  unless (open($fh,'<',$file)) {
    print "Failed to open $file\n";
    next;
  }
  while (<$fh>) {
    if (defined($files{$file})) {
      push(@{$files{$file}}, $_);
    } else {
      @{$files{$file}} = ( $_ );
    }
  }
  close($fh);
}

unless (scalar(keys(%files))) {
  print "usage:
  cat file.eml | $0
or
  $0 file.eml
or
  echo \"https://domain.com\" | $0
or
  $0 \"https://domain.com\"
or any combination of the above, including multiple arguments. eg:
  cat file.eml | $0 file.eml \"https://domain.com\" 2>/dev/null


Redirect STDERR to /dev/null to hide all information other than hit details.

Note: At the moment it only checks Quoted-Printable content\n";
  exit(0);
}

my @order = ();
if (defined($files{'STDIN'})) {
  push(@order, 'STDIN');
}
push(@order, @ARGV);

foreach my $file (@order) {
  my @uris;
  if (scalar(@order) > 1) {
    print "Checking $file...\n";
  }
  # Allow for plain URI address as entire input
  my $authority = $files{$file}[0] =~ m|(?:(?:[^:/?#]+):)?(?://([^/?#]*))|;
  if (defined($authority)) {
    push(@uris, $files{$file}[0]);
  # Otherwise, treat as an email file
  } else {
    my $body;
    foreach (@{$files{$file}}) {
      if (!defined($body)) {
        if ($_ =~ m/^$/) {
          $body = '';
          next();
        }
      } else {
        $body .= $_;
      }
    }
    $body = decode_qp($body) || die "Failed to decode $file: $?\n";
    @uris = $body =~ m|(?:(?:[^:/?#]+):)?(?://([^/?#]*))|g;
  }
  unless(scalar(@uris)) {
    print "No URIs found\n";
  }

  my @finals;
  foreach (@uris) {
    my $short = $dnslists->find_uri_shortener( $_ );
    if (defined($short) && $short != 0) {
      push(@finals, $short);
    }
    push(@finals, $dnslists->find_uri( $_ ));
  }

  my %uniq;
  foreach (@finals) {
    if (defined($uniq{$_})) {
      $uniq{$_}++;
    # Ignore whitelisted
    } elsif ($_ == 0) {
      next;
    } else {
      $uniq{$_} = 1;
    }
  }

  my $hits;
  my $count = 0;
  foreach my $uri (keys(%uniq)) {
    my ($data, $hitcount, $header) = $dnslists->check_dns($uri, 'URIRBL', "", $hits);
    if ($hitcount) {
      print STDERR sprintf("%4d", $uniq{$uri});
      my @sources = split(/,/,$header);
      my $full = '';
      foreach (@sources) {
        $full .= "$_ (" . join(' ', $rbl_levels{$_}) . "), ";
      }
      $full =~ s/, $//;
      print " $data failed - hit $full\n";
    } else {
      print STDERR sprintf("%4d %s pass\n", $uniq{$uri}, $data);
    }
  }
}
