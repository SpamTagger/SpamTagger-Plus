#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use Term::ReadKey;
use DBI;
use ReadConfig;

our $config = ReadConfig::get_instance();

my $slave_dbh = DBI->connect(
  "DBI:mysql:database=st_config;mysql_socket=".$config->get_option('VARDIR')."/run/mysql_slave/mysqld.sock",
  "spamtagger", $config->get_option('MYSPAMTAGGERPWD'), {RaiseError => 0, PrintError => 0}
);

unless ($slave_dbh) {
  printf ("ERROR: no slave database found on this system.\n");
  exit 1;
}

sub view_slaves {
  my $sth =  $slave_dbh->prepare("SELECT id, hostname, port, ssh_pub_key  FROM slave") or die ("error in SELECT");
  $sth->execute() or die ("error in SELECT");
  my $el=$sth->rows;
  while (my $ref=$sth->fetchrow_hashref()) {
    printf $ref->{'hostname'}."\n";
  }
  $sth->finish();
  return;
}

view_slaves();
