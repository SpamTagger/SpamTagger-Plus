#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
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
use ReadConfig();
use DB();

output("Starting spam syncronisation");
my $TMPDIR = "/var/tmp/spam_sync";
if ( -d $TMPDIR) {
  `rm -rf $TMPDIR/*`;
} else {
  mkdir $TMPDIR or die("could not create temoprary directory $TMPDIR");
}


my $conf = ReadConfig::get_instance();
if ($conf->get_option('ISMASTER') !~ /^[y|Y]$/) {
  print "NOTAMASTER";
  exit 0;
}

my $mconfig = DB->db_connect('source', 'st_config', 0);
my $replicasrequest = "SELECT id,hostname,port,password FROM replica";
my @replicasarray = $mconfig->get_list_of_hash($replicasrequest);
$mconfig->db_disconnect();

my $synced = 0;
foreach my $s_h (@replicasarray) {

  my $pid = fork;
  sleep 2;
  if ($pid) {
    my $sid = $s_h->{'id'};
    output("($sid) Syncing with: ".$s_h->{'hostname'}.":".$s_h->{'port'}."...");
    my %conn = ('host' => $s_h->{'hostname'}, 'port' => $s_h->{'port'}, 'password' => $s_h->{'password'}, 'database' => 'st_spool');
    my $replicadb = DB->db_connect('custom', \%conn, 0);

    ## get replica date
    my $datequery = "SELECT CURDATE() as date, CURTIME() as time";
    my %dateh = $replicadb->get_hash_row($datequery);
    my $date = '';
    my $time = '';
    if (%dateh) {
      $date = $dateh{'date'};
      $time = $dateh{'time'};
    }

    foreach my $l ('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','misc', 'num') {
      my $dumpcmd = "/usr/bin/mariadb-dump --insert-ignore -t --skip-opt -h".$s_h->{'hostname'}." -P".$s_h->{'port'}." -uspamtagger -p".$s_h->{'password'}." st_spool spam_$l -w \"in_source='0' and ( date_in < '$date' or ( date_in = '$date' and time_in < '$time') )\"";
      output("($sid) - exporting spam_$l ...");
      my $res = `$dumpcmd > $TMPDIR/spam_$l-$sid.sql`;
      if ( ! $res eq '' ) {
         print "Something went wrong while exporting spams on table: spam_$l on host ".$s_h->{'hostname'}.":\n";
         print "$res\n";
         next;
      }

      output("($sid) - reimporting spam_$l ...");
      my $exportcmd = $conf->get_option('SRCDIR')."/bin/st_mariadb -m st_spool < $TMPDIR/spam_$l-$sid.sql";
      $res = `$exportcmd`;
      if ( ! $res eq '' ) {
         print "Something went wrong while reimporting spams on table: spam_$l from host ".$s_h->{'hostname'}.":\n";
         print "$res\n";
         next;
      }

      my $updatequery = "UPDATE spam_$l SET in_source='1' WHERE in_source='0' AND ( date_in < '$date' OR ( date_in = '$date' AND time_in < '$time') )";
      my $nbres = $replicadb->{dbh}->do($updatequery);
      if (!$nbres || $nbres < 0 || $nbres !~ /^\d+$/ ) {
        $nbres = 0;
      }
      output("($sid) sync status updated for spam_$l ($nbres records).");
    }

    $replicadb->db_disconnect();
  }
  wait;
  exit if $pid;
  die "Couldn't fork: $!" unless defined($pid);
}

exit 0;

sub output ($str) {
  my $ldate = `date '+%Y-%m-%d %H:%M:%S'`;
  chomp($ldate);

  print $ldate." ".$str."\n";
  return;
}
