#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
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
#   This script will dump the exim configuration file from the configuration
#   setting found in the database.
#
#   Usage:
#           dump_greylistd_config.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use ReadConfig();
use DB();

my $conf = ReadConfig::get_instance();

my $lasterror;
my $DEBUG = 0;

my %greylist_conf = get_greylist_config() or fatal_error("NOGREYLISTDONFIGURATIONFOUND", "no greylistd configuration found");

my $uid = getpwnam( 'spamtagger' );
my $gid = getgrnam( 'spamtagger' );

dump_greylistd_file(\%greylist_conf) or fatal_error("CANNOTDUMPGREYLISTDFILE", $lasterror);

dump_domain_to_avoid($greylist_conf{'__AVOID_DOMAINS_'});

my $domainsfile = $conf->get_option('VARDIR')."/spool/tmp/spamtagger/domains_to_greylist.list";
if ( ! -f $domainsfile) {
  my $res=`touch $domainsfile`;
  chown $uid, $gid, $domainsfile;
}

print "DUMPSUCCESSFUL";

#############################
sub get_greylist_config {
  my $replica_db = DB->db_connect('replica', 'st_config');

  my %configs = $replica_db->get_hash_row(
    "SELECT retry_min, retry_max, expire, avoid_domains FROM greylistd_config"
  );
  $replica_db->db_disconnect();

  my %ret;

  $ret{'__RETRYMIN__'} = $configs{'retry_min'};
  $ret{'__RETRYMAX__'} = $configs{'retry_max'};
  $ret{'__EXPIRE__'} = $configs{'expire'};
  $ret{'__AVOID_DOMAINS_'} = $configs{'avoid_domains'};

  return %ret;
}

#############################
sub dump_domain_to_avoid ($domains) {
   my @domains_to_avoid;
   if (! $domains eq "") {
     @domains_to_avoid = split /\s*[\,\:\;]\s*/, $domains;
   }

   my $file = $conf->get_option('VARDIR')."/spool/tmp/spamtagger/domains_to_avoid_greylist.list";
   my $DOMAINTOAVOID;
   unless (open($DOMAINTOAVOID, ">", $file) ) {
    $lasterror = "Cannot open template file: $file";
    return 0;
  }
  print "$DOMAINTOAVOID $_\n" foreach (@domains_to_avoid);
  close $DOMAINTOAVOID;
  return 1;
}

#############################
sub dump_greylistd_file ($href) {
  my $srcpath = $conf->get_option('SRCDIR');
  my $varpath = $conf->get_option('VARDIR');

  my $template_file = $srcpath."/etc/greylistd/greylistd.conf_template";
  my $target_file = $srcpath."/etc/greylistd/greylistd.conf";

  my $TEMPLATE;
  unless (open($TEMPLATE, "<", $template_file) ) {
    $lasterror = "Cannot open template file: $template_file";
    return 0;
  }
  my $TARGET;
  unless (open($TARGET, ">", $target_file) ) {
    $lasterror = "Cannot open target file: $target_file";
    close $template_file;
    return 0;
  }

  while(my $line = <$TEMPLATE>) {

    $line =~ s/__VARDIR__/$varpath/g;
    $line =~ s/__SRCDIR__/$srcpath/g;

    foreach my $key (keys %{$href}) {
      $line =~ s/$key/$href->{$key}/g;
    }

    print $TARGET $line;
  }

  close $TEMPLATE;
  close $TARGET;

  chown $uid, $gid, $target_file;
  return 1;
}

#############################
sub fatal_error ($msg, $full) {
  print $msg;
  print "\n Full information: $full \n" if ($DEBUG);
  exit(0);
}

#############################
sub print_usage {
  print "Bad usage: dump_exim_config.pl [stage-id]\n\twhere stage-id is an integer between 0 and 4 (0 or null for all).\n";
  exit(0);
}
