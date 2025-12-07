#!/usr/bin/env perl -I../lib/
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
#
#
#   This script will dump the domains configuration
#
#   Usage:
#           dump_domains.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use ReadConfig();
use DB();
use SystemPref();
use File::Copy();

my $domain = shift;

my $uid = getpwnam( 'spamtagger' );
my $gid = getgrnam( 'spamtagger' );

my $conf = ReadConfig::get_instance();
my $op = $conf->get_option('SRCDIR');

our $replica_db = DB->db_connect('replica', 'st_config');

dump_archived_domains();
dump_copy_to();
dump_bypass_filtering();

$replica_db->db_disconnect();
print "DUMPSUCCESSFUL";
exit 0;

#####################################
## dump_archived_domains
sub dump_archived_domains {
  my @adomains = $replica_db->get_list_of_hash("SELECT d.name FROM domain d, domain_pref dp WHERE dp.archive_mail='1' AND d.name != '__global__' AND d.prefs=dp.id");

  my $archive_path = $conf->get_option('VARDIR')."/spool/tmp/exim_stage1/archiver";
  if (! -d $archive_path) {
    mkdir($archive_path);
  }
  if (defined($archive_path) && $archive_path ne '') {
    `rm $archive_path/* >/dev/null 2>&1`;
  }

  my %doms;
  foreach my $d (@adomains) {
    my $domfile = $archive_path."/".$d->{'name'};
    my $DFILE;
    if (open($DFILE, ">", $domfile) ) {
      print $DFILE "*";
      close $DFILE;
      $doms{$d->{'name'}} = 1;
    }
  }

  my @aemail = $replica_db->get_list_of_hash("SELECT address from email e, user_pref p WHERE p.archive_mail=1 AND e.pref=p.id");
  foreach my $e (@aemail) {
    if (defined($e->{'address'}) && $e->{'address'} =~ /(\S+)\@(\S+)/) {
      my $edom = $2;
      my $euser = $1;
      unless (defined($doms{$edom})) {
        my $domfile = $archive_path."/".$edom;
        my $DFILE;
        if (open($DFILE, ">>", $domfile)) {
          print $DFILE $e->{'address'}."\n";
          print $DFILE $euser."\n";
          close $DFILE;
        }
      }
    }
  }
  return;
}

#####################################
## dump_copy_to
sub dump_copy_to {
  my @cdomains = $replica_db->get_list_of_hash("SELECT d.name, dp.copyto_mail FROM domain d, domain_pref dp WHERE dp.copyto_mail != '' AND d.name != '__global__' AND d.prefs=dp.id");

  my $copyto_path = $conf->get_option('VARDIR')."/spool/tmp/exim_stage1/copyto";
  if (! -d $copyto_path) {
    mkdir($copyto_path);
  }
  if (defined($copyto_path) && $copyto_path ne '') {
    `rm $copyto_path/* >/dev/null 2>&1`;
  }

  my %doms;
  foreach my $d (@cdomains) {
    my $domfile = $copyto_path."/".$d->{'name'};
    my $DFILE;
    if (open($DFILE, ">", $domfile)) {
      print $DFILE "*:".$d->{'copyto_mail'};
      close $DFILE;
      $doms{$d->{'name'}} = 1;
    }
  }

  my @cemail = $replica_db->get_list_of_hash("SELECT e.address, p.copyto_mail from email e, user_pref p WHERE p.copyto_mail != '' AND e.pref=p.id");
  foreach my $e (@cemail) {
    if (defined($e->{'address'}) && $e->{'address'} =~ /(\S+)\@(\S+)/) {
      my $edom = $2;
      my $euser = $1;
      unless (!defined($doms{$edom})) {
        my $domfile = "$copyto_path/$edom";
        my $DFILE;
        if (open($DFILE, ">>", $domfile)) {
          print $DFILE $e->{'address'}.":".$e->{'copyto_mail'}."\n";
          print $DFILE $euser.":".$e->{'copyto_mail'}."\n";
          close $DFILE;
        }
      }
    }
  }
  return;
}

#####################################
## dump_bypass_filtering
sub dump_bypass_filtering {

  my $bypassfiltering_path = $conf->get_option('VARDIR')."/spool/tmp/exim_stage1/bypass";

  my @cemail = $replica_db->get_list_of_hash("SELECT e.address, p.bypass_filtering from email e, user_pref p WHERE p.bypass_filtering != '' AND e.pref=p.id");

  if (defined($bypassfiltering_path) && $bypassfiltering_path ne '') {
    if ( ! -d $bypassfiltering_path ) {
       mkdir($bypassfiltering_path);
    }
    `rm $bypassfiltering_path/* >/dev/null 2>&1`;
  }

  foreach my $e (@cemail) {
    if (defined($e->{'address'}) && $e->{'address'} =~ /(\S+)\@(\S+)/) {
      my $edom = $2;
      my $euser = $1;
      my $domfile = $bypassfiltering_path."/".$edom;
      my $DFILE;
      if (open($DFILE, ">>", $domfile) ) {
        print $DFILE $euser."\n";
        close $DFILE;
      }
    }
  }
  return;
}

