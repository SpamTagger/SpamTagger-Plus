#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use File::Basename;

my $alarm_limit = 85;

my $script_name         = basename($0);
my $script_name_no_ext  = $script_name;
$script_name_no_ext     =~ s/\.[^.]*$//;
my $timestamp           = time();
my $rc = 0;

my $PID_FILE = '/var/spamtagger/run/watchdog/' . $script_name_no_ext . '.pid';
my $OUT_FILE = '/var/spamtagger/spool/watchdog/' .$script_name_no_ext. '_' .$timestamp. '.out';

open my $file, '>', $OUT_FILE;

sub my_own_exit ($exit_code = 0) {
  unlink $PID_FILE if ( -e $PID_FILE );

  my $ELAPSED = time() - $timestamp;
  print $file "EXEC : $ELAPSED\n";
  print $file "RC : $exit_code\n";

  close $file;

  exit($exit_code);
}

my @df = `df -h`;
chomp(@df);
foreach my $line (@df) {
  my (undef, $size, $used, undef, $pc, $mount) = split(' ', $line, 6);
  $pc =~ s/%//;

  if ( ($mount eq '/') || ($mount eq '/var') ) {
    if ( $pc >= $alarm_limit ) {
      print $file "$mount : $used / $size => $pc\n";
      $rc = 1;
    }
  }
}

my_own_exit($rc);
