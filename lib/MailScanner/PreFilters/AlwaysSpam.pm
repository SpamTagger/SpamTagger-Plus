#!/usr/bin/env perl

package MailScanner::AlwaysSpam;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

our $MODULE = 'AlwaysSpam';

sub initialise ($class = $MODULE) {
  MailScanner::Log::InfoLog("$class module initializing...");
  return bless {}, $class;
}

# TODO: Mixed case function name, hard-coded into MailScanner. Ignore in Perl::Critic
sub Checks ($this, $message) { ## no critic
  MailScanner::Log::InfoLog(blessed($this).' module checking... well guess what ? it\'s spam !');
  return 1;
}

sub dispose ($this) {
  MailScanner::Log::InfoLog(blessed($this).' module disposing...');
  return;
}

1;
