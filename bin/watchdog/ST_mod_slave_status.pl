#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use File::Basename;

my $script_name         = basename($0);
my $script_name_no_ext  = $script_name;
$script_name_no_ext     =~ s/\.[^.]*$//;
my $timestamp           = time();

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

my $slave_status = `echo 'show slave status\\G' |/usr/spamtagger/bin/st_mariadb -s`;

if ($slave_status eq '') {
  # Réparer resync_db.sh
  print $file "Show slave status : Retour vide, faire un sync_db\n";
  my_own_exit(1);
} elsif ( ($slave_status !~ /Slave_SQL_Running: Yes/) || ($slave_status !~ /Slave_IO_Running: Yes/) ) {
  print $file "Show slave status : au moins un des process retourne No, faire un sync_db\n";
  my_own_exit(2);
}

my_own_exit(0);
