#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib';
use ManageServices;

sub get_date {
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
  $mon++;
  $year += 1900;
  return sprintf( "%d-%.2d-%.2d %.2d:%.2d:%.2d", $year, $mon, $mday, $hour, $min, $sec );
}

my $manager = ManageServices->new( 'autoStart' => 1 ) || die "Failed to create object: $!\n";
my $log = '/var/log/service_check.log';
my $lock = '/var/spamtagger/spool/tmp/service_check.lock';
my $cron = '/var/spamtagger/spool/tmp/spamtagger_cron.lock';
my $update = '/var/spamtagger/spool/spamtagger/updater4mc.status';
my $date = get_date();
my ($LOG, $LOCK);

open ($LOG, '>>', $log) || die "Could not open log file $log\n";

foreach my $file ( $lock, $cron, $update ) {
  if ( -e $file ) {
    if ( $file eq $lock && ((stat($lock))[9] < (time() - 600)) ) {
      print("Lock file $lock is old. Removing...\n");
      unlink($lock);
    } else {
      print $LOG "$date - Service check currently blocked by $file.\n";
      print "Service check currently blocked by $file.\n";
      close($LOG);
      exit(0);
    }
  }
}

unless (open($LOCK, '>', $lock)) {
  print $LOG "$date - Could not create lock file: $!\n";
  print "Could not create lock file: $!\n";
  close($LOG);
  exit();
}
close($LOCK);

my $status = $manager->check_all();
foreach my $service (keys %$status) {
  if ( $status->{$service} != 1 ) {
    print $LOG "$date - $service: ".$manager->{'codes'}->{$status->{$service}}->{'verbose'}."\n";
  }
}
my $tries = 0;
unlink($lock) || die "Failed to remove lockfile: $!";
close($LOG);
