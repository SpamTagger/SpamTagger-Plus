#!/usr/bin/env perl

package MailScanner::AlwaysSpam;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

sub initialise {
  MailScanner::Log::InfoLog('AlwaysSpam module initializing...');
  return;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($message) { ## no critic
  MailScanner::Log::InfoLog('AlwaysSpam module checking... well guess what ? it\'s spam !');
  return 1;
}

sub dispose {
  MailScanner::Log::InfoLog('AlwaysSpam module disposing...');
  return;
}

1;
