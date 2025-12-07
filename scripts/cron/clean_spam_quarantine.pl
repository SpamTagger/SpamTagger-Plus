#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib';
use Date::Calc qw ( Today Delta_Days Localtime Time_to_Date );
use String::ShellQuote qw( shell_quote );
use File::stat();
use DB();
use ReadConfig();

my $config = ReadConfig::get_instance();
my $VARDIR = $config->get_option('VARDIR');

my $days_to_keep = shift;

my $quarantine_owner_name = 'spamtagger';
my $quarantine_owner      = getpwnam($quarantine_owner_name);
my $quarantine_group      = getgrnam($quarantine_owner_name);

our $has_ipc_run = eval
{
  require IPC::Run;
  1;
};

my $DEBUG = 0;
if ( !$days_to_keep ) {
  my $config_dbh = DB->db_connect('replica', 'st_config');
  if ($config_dbh) {
    my $config_sth =
      $config_dbh->prepare("SELECT days_to_keep_spams FROM system_conf");
    $config_sth->execute();
    while ( my $ref_config = $config_sth->fetchrow_hashref() ) {
      $days_to_keep = $ref_config->{'days_to_keep_spams'};
    }
    $config_sth->finish();
    $config_dbh->db_disconnect();
  }
  if ( !$days_to_keep ) {
    $days_to_keep = 60;
  }
}

my $quarantine_dir = "$VARDIR/spam";

# Standardise the format of the directory name
die 'Path for quarantine_dir must be absolute' unless $quarantine_dir =~ /^\//;
$quarantine_dir =~ s/\/$//;    # Delete trailing slash

## delete in databases
my @dbs = ( 'replica', 'source' );
foreach my $db (@dbs) {
  my $dbh = DB->db_connect($db, 'st_spool');
  if ($dbh) {
    foreach my $letter (
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
      'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
      'u', 'v', 'w', 'x', 'y', 'z', 'misc', 'num',
    ) {
      print "cleaning letter: $letter\n";
      my $sth = $dbh->prepare(
        "DELETE FROM spam_$letter WHERE TO_DAYS(NOW())-TO_DAYS(date_in) > $days_to_keep"
      );
      $sth->execute();
      $sth->finish();
    }
    $dbh->db_disconnect();
  }
}

## delete real files
my $QDIR;
opendir($QDIR, $quarantine_dir )
  or die "Couldn't read directory $quarantine_dir";
while ( my $entry = readdir($QDIR) ) {
  next if $entry =~ /^\./;
  $entry = $quarantine_dir . '/' . $entry;
  if ( -d $entry ) {
    my $DDIR;
    opendir($DDIR, $entry ) or die "Couldn't read directory $entry";
    while ( my $domain_entry = readdir($DDIR) ) {
      next if $domain_entry =~ /^\./;
      $domain_entry = $entry . '/' . $domain_entry;

      if ( -d $domain_entry ) {
        my $UDIR;
        opendir($UDIR, $domain_entry )
          or die "Couldn't read directory $domain_entry";
        while ( my $user_entry = readdir($UDIR) ) {
          next if $user_entry =~ /^\./;

          $user_entry = $domain_entry . '/' . $user_entry;
          my @statsa = stat($user_entry);
          my @stats = @{$statsa[0]};
          my @date  = Time_to_Date( $stats[9] );
          my $ddays =
            Delta_Days( ( $date[0], $date[1], $date[2] ), Today() );
            if ($ddays > $days_to_keep) {
              if ($has_ipc_run) {
                IPC::Run::run(["rm", "$user_entry"], "2>&1", ">/dev/null");
              } else {
                system("rm ".shell_quote($user_entry)." 2>&1 >/dev/null");
              }
            }
        }
        close($UDIR);
      }
      my $uid = stat($domain_entry)->uid;
      if ( $uid != $quarantine_owner ) {
        chown $quarantine_owner, $quarantine_group, $domain_entry;
      }
      my $gid = stat($domain_entry)->gid;
      if ( $gid != $quarantine_group ) {
        chown $quarantine_owner, $quarantine_group, $domain_entry;
      }
      if ($has_ipc_run) {
        IPC::Run::run(["rmdir", "$domain_entry"], "2>&1", ">/dev/null");
      } else {
        system("rmdir ".shell_quote($domain_entry)." 2>&1 >/dev/null");
      }
    }
    close($DDIR);
    my $uid = stat($entry)->uid;
    if ( $uid != $quarantine_owner ) {
      chown $quarantine_owner, $quarantine_group, $entry;
    }
    my $gid = stat($entry)->gid;
    if ( $gid != $quarantine_group ) {
      chown $quarantine_owner, $quarantine_group, $entry;
    }
    $entry =~ s/\|/\\\|/;
    if ($has_ipc_run) {
      IPC::Run::run(["rmdir", "$entry"], "2>&1", ">/dev/null");
    } else {
      system("rmdir ".shell_quote($entry)." 2>&1 >/dev/null");
    }
  }
}
closedir($QDIR);
exit;
