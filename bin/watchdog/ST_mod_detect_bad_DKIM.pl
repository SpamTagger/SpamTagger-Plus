#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use File::Basename;

my $min_length = 1024;

my $script_name         = basename($0);
my $script_name_no_ext  = $script_name;
$script_name_no_ext     =~ s/\.[^.]*$//;
my $timestamp           = time();

my $PID_FILE   = '/var/spamtagger/run/watchdog/' . $script_name_no_ext . '.pid';
my $OUT_FILE   = '/var/spamtagger/spool/watchdog/' .$script_name_no_ext. '_' .$timestamp. '.out';

open my $file, '>', $OUT_FILE;

sub my_own_exit ($exit_code = 0) {
  unlink $PID_FILE if ( -e $PID_FILE );

  my $ELAPSED = time() - $timestamp;
  print $file "EXEC : $ELAPSED\n";
  print $file "RC : $exit_code\n";

  close $file;

  exit($exit_code);
}

my $dir;
opendir($dir, '/var/spamtagger/spool/tmp/spamtagger/dkim/');
my @short;
my @invalid;
while (my $key = readdir($dir)) {
  next if ($key eq 'default.pkey' && -s "/var/spamtagger/spool/tmp/spamtagger/dkim/$key" <= 1);
  next if ($key =~ m/^\.+$/);
  my $length = `openssl rsa -in /var/spamtagger/spool/tmp/spamtagger/dkim/$key -noout -text 2> /dev/null | grep 'Private-Key:'` || 'invalid';
  chomp($length);
  $length =~ s/Private-Key: \((\d+) bit\)/$1/;
  if ($length =~ m/^\d+$/) {
    push(@short, $key) if ($length < $min_length);
  } else {
    push(@invalid, $key);
  }
}

my $status = '';
my $rc = 0;
if (scalar(@short)) {
  $rc += 1;
  $status .= 'Short DKIM key length: ' . join(', ', @short);
}
if (scalar(@invalid)) {
  $status .= '<br/>' if ($rc);
  $rc += 2;
  $status .= 'Invalid DKIM key: ' . join(', ', @invalid);
}

print $file $status."\n" if ($status);

my_own_exit($rc);
