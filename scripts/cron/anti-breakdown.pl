#! /usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2015-2018 Pascal Rolle <rolle@spamtagger.org>
#   Copyright (C) 2015-2018 Mentor Reka <reka@spamtagger.org>
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
#   This is the anti-breakdown script. To be run every 15 minutes

use v5.40;
use warnings;
use utf8;

# TODO: teporarily disable for spamtagger transition
die "Feature not currently supported by SpamTagger";

=pod Ignore for perlcritic
push(@INC, '/usr/spamtagger/lib/');
use Net::DNS();
use Net::Ping();
use File::Touch();
use DB();
use ReadConfig();

our $config = ReadConfig::get_instance();
my $max_host_failed = 2;
my $nb_tests = 3;
my $is_dns_ok = 0;
my $is_data_ok = 0;
my $dns_ko_file    = '/var/tmp/st_checks_dns.ko';
my $data_ko_file  = '/var/tmp/sstchecks_data.ko';
my $rbl_sql_file  = '/var/tmp/st_checks_rbls.bak';
my @rbls_to_disable  = qw/STIPRWL STIPRBL SIPURIRBL STURIBL STERBL SIPINVALUEMENT SIPDEUXQUATREINVALUEMENT STTRUSTEDSPF/;

my %rbl_field = (
  'trustedSources' => 'whiterbls',
  'PreRBLs' => 'lists',
  'UriRBLs' => 'rbls',
  'mta_config' => 'rbls',
  'antispam' => 'sa_rbls'
);

sub check_host ($host, $port) {
  my $p = Net::Ping->new('tcp', 5);
  $p->port_number($port);
  my $res = $p->ping($host);

  undef($p);

  return $res;
}


sub is_dns_service_available ($host) {
  my $res = Net::DNS::Resolver->new(
    tcp_timeout => 5,
    retry       => 3,
    retrans     => 1,
    recurse     => 0,
    debug       => 0
  );

  $res->nameservers($host);

  if ( $res->send("spamtagger.org", 'MX') ) {
    return 1;
  } else {
    return 0;
  }
}

# retourne false si 3 tentatives KO
sub is_port_ok ($step, $port, @hosts) {
  my $nb_failed_host = 0;

  foreach my $host (@hosts) {
    if ($port == 53) {
      if ( ! is_dns_service_available($host) ) {
        $nb_failed_host++;
      }
    } elsif ( ! check_host($host, $port) ) {
      $nb_failed_host++;
    }
  }
  if  ( $nb_failed_host >= $max_host_failed) {
    system("/usr/sbin/rndc", "flush");
    $step++;
    if ($step == $nb_tests) {
      return 0;
    }

    sleep 5;
    return ( is_port_ok($step, $port, @hosts) ) ;
  }
  return 1;
}

sub remove_and_save_ST_RBLs {
  my $sth;
  my $reboot_service = 0;

  my $master_dbh = DB->db_connect('master', 'st_config');
  if ( ! defined($master_dbh) ) {
    warn "CANNOTCONNECTMASTERDB\n", $master_dbh->errstr;
    return 0;
  }

  open(my $FH, '>', $rbl_sql_file);

  foreach my $table (keys %rbl_field) {
    my $field = $rbl_field{$table};

    $sth = $master_dbh->prepare("select $field from $table;");
    $sth->execute() or return 0;
    my $ref = $sth->fetchrow_hashref();
    my $original_field = $ref->{$field};
    $original_field =~ s/\s+/ /g;
    $original_field =~ s/\s*$//;
    my @rbls = split(' ', $original_field);

    my $nw;
    foreach my $w (@rbls) {
      if ( scalar( grep {/$w/} @rbls_to_disable) > 0 ) {
        print $FH "update $table set $field = concat($field, ' $w');\n";
      } else {
        $nw .= "$w ";
      }
    }
    $nw =~ s/\s*$//;

    if ($nw ne $original_field) {
      $sth = $master_dbh->prepare("update $table set $field ='$nw';");
      $sth->execute();
      $reboot_service = 1;
    }
  }
  close $FH;

  $sth->finish() if ( defined($sth) );
  $master_dbh->db_disconnect();

  if ($reboot_service) {
    system('/usr/spamtagger/etc/init.d/mailscanner', 'restart');
  }
}

# DNS service is ok, if the previous state was KO, we enable back the RBLs which were formely configured
sub handle_dns_ok {
  # reimport all saved rbls (/var/tmp/st_checks_rbls.bak)
  if ( -e $rbl_sql_file ) {
    my $sth;

    # Database connexion
    my $master_dbh = DB->db_connect('master', 'st_config');
    if ( ! defined($master_dbh) ) {
      warn "CANNOTCONNECTMASTERDB\n", $master_dbh->errstr;
      return 0;
    }

    # The file contains the SQL statements ready to be excuted
    open(my $FH, $rbl_sql_file or warn "Cannot open $rbl_sql_file: $!\n";
    while (<$FH>) {
      $sth = $master_dbh->prepare($_);
      $sth->execute();
    }
    close $FH;

    $sth->finish() if ( defined($sth) );
    $master_dbh->db_disconnect();

    # Restarting associated services
    system('/usr/spamtagger/etc/init.d/mailscanner', 'restart');

    # Removing temp files
    unlink $rbl_sql_file or warn "could not remove $rbl_sql_file\n";
    unlink $dns_ko_file or warn "could not remove $dns_ko_file\n";;
  }
}

# DNS service is KO. We remove RBLs hosted by SpamTagger from the configuration
sub handle_dns_ko {
  # There is nothing to do if SpamTagger was already away
  return if ( -e $dns_ko_file );

  # Creating the DNS KO flag file : /var/tmp/st_checks_dns.ko
  touch($dns_ko_file);

  # Removes and saves the RBLs hosted by SpamTagger then restarts associated services
  remove_and_save_st_rbls();
}

# SpamTagger servers used for updating scripts and data are offline
# We set a flag which will prevent associated services to run
sub handle_data_ko {
  # Creating the Data KO flag file : /var/tmp/st_checks_data.ko
  touch($data_ko_file);
}

sub handle_data_ok {
  unlink $data_ko_file;
}
=cut
