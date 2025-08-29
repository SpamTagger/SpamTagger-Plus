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

use lib '/usr/spamtagger/lib/';
use STDnsLists();
use DB();
use IO::Interactive();

# Necessary configuration items
my $config = {
  'rbls' => '',
  'rblsDefsPath' => '',
  'whitelistDomainsFile' => '',
  'TLDsFiles' => '',
  'localDomainsFile' => ''
};

# Get values from file
my $configfile = "$SRCDIR/etc/mailscanner/prefilters/PreRBLs.cf";
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
my $db = DB->db_connect('slave', 'st_config');
my %mta_row = $db->get_hash_row("SELECT rbls FROM mta_config WHERE stage=1");
die "Failed to fetch SMTP config\n" unless %mta_row;

my %pre_row = $db->get_hash_row("SELECT lists FROM PreRBLs");
die "Failed to fetch PreRBLs config\n" unless %pre_row;

my %spamc_row = $db->get_hash_row("SELECT sa_rbls FROM antispam");
die "Failed to fetch SpamC config\n" unless %spamc_row;

# Assemble RBL sources for each level of filtering
my %rbl_sources = (
  'SMTP'    => [ split(/\s+/, $mta_row{rbls}) ],
  'PreRBLs' => [ split(/\s+/, $pre_row{lists}) ],
  'SpamC'   => [ split(/\s+/, $spamc_row{sa_rbls}) ]
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
$dnslists->load_rbls( $config->{rblsDefsPath}, $config->{rbls}, 'IPRBL DNSRBL BSRBL', $config->{whitelistDomainsFile}, $config->{TLDsFiles}, $config->{localDomainsFile}, $0);

# Build input hash
my $current;
my %files;

# Load STDIN, if provided
if (IO::Interactive::is_interactive()) {
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
  my $fh;
  if ($file =~ m/((?:\d+\.){3}(?:\d+))/g) {
    @{$files{$file}} = ( $file );
    next;
  }
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
  echo 1.2.3.4 | $0
or
  $0 1.2.3.4
or any combination of the above, including multiple arguments. eg:
  cat file.eml | $0 file.eml 1.2.3.4 5.6.7.8 2>/dev/null


Redirect STDERR to /dev/null to hide all information other than hit details.\n";
  exit(0);
}

my @order = ();
if (defined($files{'STDIN'})) {
  push(@order, 'STDIN');
}
push(@order, @ARGV);

foreach my $file (@order) {
  my @ips;
  if (scalar(@order) > 1) {
    print "Checking $file...\n";
  }
  # Allow for plain IPv4 address as entire input
  if (scalar(@{@files{$file}}) == 1 && $files{$file}[0] =~ m/((?:\d+\.){3}(?:\d+))/g) {
    chomp($files{$file}[0]);
    push(@ips, $files{$file}[0]);
  # Otherwise, treat as an email file
  } else {
    foreach my $line (@{$files{$file}}) {
      if ($line =~ m/Received:/i) {
        if (defined($current)) {
          if (my @matches = $current =~ m/((?:\d+\.){3}(?:\d+))/g) {
            push(@ips, reverse(@matches));
          }
          if (my @matches = $current =~ m/((?:[\da-fA-F]{4}:)+(?::?[\da-fA-F]{4})+)/g) {
            push(@ips, reverse(@matches));
          }
          $current = undef;
        }
        $current .= $line;
      } elsif ($line =~ m/^\s/ && defined($current)) {
        $current .= $line;
      } elsif (defined($current)) {
        if (my @matches = $current =~ m/((?:\d+\.){3}(?:\d+))/g) {
          push(@ips, reverse(@matches));
        }
        if (my @matches = $current =~ m/((?:[\da-fA-F]{4}:)+(?::?[\da-fA-F]{4})+)/g) {
          push(@ips, reverse(@matches));
        }
        $current = undef;
      }
      last if ($line =~ /^$/);
    }
  }
  die "No 'Received' IPs found\n" unless(scalar(@ips));

  my $hits;
  my $count = 0;
  foreach (@ips) {
    my ($data, $hitcount, $header) = $dnslists->check_dns($_, 'IPRBL', "", $hits);
    if ($hitcount) {
      print STDERR sprintf("Received %3d", $count--);
      my @sources = split(/,/,$header);
      my $full = '';
      foreach (@sources) {
        $full .= "$_ (" . join(' ', $rbl_levels{$_}) . "), ";
      }
      $full =~ s/, $//;
      print " $data failed - hit $full\n";
    } else {
      print STDERR sprintf("Received %3d %s pass\n", $count--, $data);
    }
  }
}
