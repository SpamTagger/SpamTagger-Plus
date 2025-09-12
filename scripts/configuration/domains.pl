#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib';
use DB();
use Term::ReadKey;
use ReadConfig;

my $config = ReadConfig::get_instance();
my $VARDIR = $config->get_option('VARDIR');

our $master_dbh = DB->db_connect('master', 'st_config');
if (!$master_dbh) {
  printf ("ERROR: no master database found on this system. This script will only run on a SpamTagger master host.\n");
  exit 1;
}

my $quit=0;
while (! $quit) {
  system("clear");
  printf "\n################################\n";
  printf "## SpamTagger domain manager ##\n";
  printf "################################\n\n";
  printf "1) view domains\n";
  printf "2) delete domain\n";
  printf "3) add domain\n";
  printf "q) quit\n";
  printf "\nEnter your choice: ";

  ReadMode 'cbreak';
  my $key = ReadKey(0);
  ReadMode 'normal';

  if ($key =~ /q/) {
    $quit=1;
  } elsif ($key =~ /1/) {
    view_domains();
  } elsif ($key =~ /2/) {
    delete_domain();
  } elsif ($key =~ /3/) {
    add_domain();
  } elsif ($key =~ /4/) {
    synchronize_slaves();
  }
}

printf "\n\n";

$master_dbh->db_disconnect();

exit 0;

sub view_domains {
  system("clear");
  my $sth =  $master_dbh->prepare("SELECT id, name, active, destination, prefs FROM domain ORDER BY name") or die ("error in SELECT");
  $sth->execute() or die ("error in SELECT");
  my $el=$sth->rows;
  printf "Domain list: ($el element(s))\n";
  while (my $ref=$sth->fetchrow_hashref()) {
    printf $ref->{'id'}."-\t".$ref->{'name'}."\t\t".$ref->{'destination'}."\n";
  }
  $sth->finish();
  printf "\n******\ntype any key to return to main menu";
  ReadMode 'cbreak';
  my $key = ReadKey(0);
  ReadMode 'normal';
  return;
}

sub delete_domain {
  system("clear");
  printf "Please enter domain id to delete: ";
  my $d_id = ReadLine(0);
  $d_id =~ s/^\s+//;
  $d_id =~ s/\s+$//;

  my $sth =  $master_dbh->prepare("DELETE FROM domain WHERE id='$d_id'");
  if (! $sth->execute()) {
    printf "no domain deleted..\n";
  } else {
    printf "domain $d_id deleted.\n";
    $sth->finish();
  }
  printf "\n******\ntype any key to return to main menu";
  ReadMode 'cbreak';
  my $key = ReadKey(0);
  ReadMode 'normal';
  return;
}

sub add_domain {
  system("clear");
  printf "Enter domain name: ";
  my $name = ReadLine(0);
  $name =~ s/^\s+//;
  $name =~ s/\s+$//;
  printf "Enter destination server: ";
  my $destination = ReadLine(0);
  $destination =~ s/^\s+//;
  $destination =~ s/\s+$//;

  if ( $name =~ /^[A-Z,a-z,0-9,\.,\_,\-,\*]{1,200}$/) {

    my $sth =  $master_dbh->prepare("INSERT INTO domain_pref SET auth_server='$destination', auth_modif='att_add'");
    if (!$sth->execute()) {
      printf "Domain prefs NOT added !\n";
      return;
    }
    $sth =  $master_dbh->prepare("SELECT LAST_INSERT_ID() id");
    if (!$sth->execute()) {
      printf "Domain prefs could NOT be found !\n";
      return;
    }
    my $ref=$sth->fetchrow_hashref();
    if (!$ref) {
      printf "Domain prefs array could NOT be found !\n";
      return;
    }

    $sth =  $master_dbh->prepare("INSERT INTO domain (name, destination, prefs) VALUES('$name', '$destination', '".$ref->{'id'}."')");
    if (!$sth->execute()) {
      printf "Domain NOT added !\n";
    } else {
      printf "Domain $name added.\n";
      $sth->finish();
    }
  } else {
    printf "please enter a domain name !\n";
  }
  printf "\n******\ntype any key to return to main menu";
  ReadMode 'cbreak';
  my $key = ReadKey(0);
  ReadMode 'normal';
  return;
}
