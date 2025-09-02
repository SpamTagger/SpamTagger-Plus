#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004-2014 Olivier Diserens <olivier@diserens.ch>
#   Copyright (C) 2015-2017 Florian Billebault <florian.billebault@gmail.com>
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
#   This script will dump the apache config file with the configuration
#   settings found in the database.
#
#   Usage:
#     dump_apache_config.pl

use v5.40;
use warnings;
use utf8;

my $DEBUG = 1;

use lib '/usr/spamtagger/lib/';
use DB();
use ReadConfig();

our $config = ReadConfig::get_instance();
our $VARDIR = $config->get_option('VARDIR');
our $SRCDIR = $config->get_option('SRCDIR');
our $MYSPAMTAGGERPWD = $config->get_option('MYSPAMTAGGERPWD');
our $HOSTID = $config->get_option('HOSTID');

my $lasterror = "";

our $dbh = DB->db_connect('slave', 'st_config') or fatal_error("CANNOTCONNECTDB", $dbh->errstr);

my %sys_conf = get_system_config() or fatal_error("NOSYSTEMCONFIGURATIONFOUND", "no record found for system configuration");

my %apache_conf;
%apache_conf = get_apache_config() or fatal_error("NOAPACHECONFIGURATIONFOUND", "no apache configuration found");

dump_apache_file("/etc/apache/httpd.conf_template", "/etc/apache/httpd.conf") or fatal_error("CANNOTDUMPAPACHEFILE", $lasterror);

if (-e "$config{'SRCDIR'}/etc/apache/sites/spamtagger.conf.disabled") {
  unlink("$config{'SRCDIR'}/etc/apache/sites/spamtagger.conf");
} else {
  dump_apache_file("/etc/apache/sites/spamtagger.conf_template", "/etc/apache/sites/spamtagger.conf") or fatal_error("CANNOTDUMPAPACHEFILE", $lasterror);
}

if (-e "$config{'SRCDIR'}/etc/apache/sites/configurator.conf.disabled") {
  unlink("$config{'SRCDIR'}/etc/apache/sites/configurator.conf");
} else {
  dump_apache_file("/etc/apache/sites/configurator.conf_template", "/etc/apache/sites/configurator.conf") or fatal_error("CANNOTDUMPAPACHEFILE", $lasterror);
}

dump_soap_wsdl() or fatal_error("CANNOTDUMPWSDLFILE", $lasterror);

dump_certificate($apache_conf{'tls_certificate_data'}, $apache_conf{'tls_certificate_key'}, $apache_conf{'tls_certificate_chain'});

$dbh->db_disconnect();

print "DUMPSUCCESSFUL";

#############################
sub dump_apache_file ($filetmpl, $filedst) {
  my $template_file = "${SRCDIR}${filetmpl}";
  my $target_file = "${SRCDIR}${filedst}";

  unless (open(my $TEMPLATE, "<", $template_file) ) {
    $lasterror = "Cannot open template file: $template_file";
    return 0;
  }

  unless (open(my $TARGET, ">", $target_file) ) {
    $lasterror = "Cannot open target file: $target_file";
    close $template_file;
    return 0;
  }

  my $inssl = 0;
  while(my $line = <$TEMPLATE>) {
    $line =~ s/__VARDIR__/$VARDIR/g;
    $line =~ s/__SRCDIR__/$SRCDIR/g;
    $line =~ s/__DBPASSWD__/$MYSPAMTAGGERPWD/g;

    $line =~ s/$_/$sys_conf{$_}/g foreach (keys(%sys_conf));

    $line =~ s/$_/$apache_conf{$_}/g foreach (keys(%apache_conf));

    if ($line =~ /^\_\_IFSSLCHAIN\_\_(.*)/) {
      if ($apache_conf{'tls_certificate_chain'} && $apache_conf{'tls_certificate_chain'} ne '') {
        print $TARGET $1."\n";
      }
      next;
    }

    if ($line =~ /\_\_IFSSL\_\_/) {
      $inssl = 1;
      next;
    }

    if ($line =~ /\_\_ENDIFSSL\_\_/) {
      $inssl = 0;
      $line = "";
      next;
    }

    print TARGET $line if ( (! $inssl) || ($apache_conf{'__USESSL__'} =~ /true/) );
  }

  close $TEMPLATE;
  close $TARGET;

  return 1;
}

sub dump_soap_wsdl {
  my $template_file = "$SRCDIR/www/soap/htdocs/spamtagger.wsdl_template";
  my $target_file = "$SRCDIR/www/soap/htdocs/spamtagger.wsdl";

  unless (open(my $TEMPLATE, "<", $template_file) ) {
    $lasterror = "Cannot open template file: $template_file";
    return 0;
  }
  unless (open(my $TARGET, ">", "$target_file") ) {
    $lasterror = "Cannot open target file: $target_file";
    close $template_file;
    return 0;
  }

  my $inssl = 0;
  while(my $line = <$TEMPLATE>) {
    $line =~ s/__HOST__/$sys_conf{'HOST'}/g;
    print $TARGET $line;
  }

  close $TEMPLATE;
  close $TARGET;

  return 1;
}

#############################
sub get_system_config {
  my %config;

  my $sth = $dbh->prepare("SELECT hostname, default_domain, sysadmin, clientid FROM system_conf");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  return if ($sth->rows < 1);
  my $ref = $sth->fetchrow_hashref() or return;

  $config{'__PRIMARY_HOSTNAME__'} = $ref->{'hostname'};
  $config{'__QUALIFY_DOMAIN__'} = $ref->{'default_domain'};
  $config{'__QUALIFY_RECIPIENT__'} = $ref->{'sysadmin'};
  $config{'__CLIENTID__'} = $ref->{'clientid'};

  $sth->finish();

  $sth = $dbh->prepare("SELECT hostname FROM slave WHERE id=".$HOSTID);
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);
  return if ($sth->rows < 1);
  $ref = $sth->fetchrow_hashref() or return;
  $config{'HOST'} = $ref->{'hostname'};
  $sth->finish();

  return %config;
}

#############################
sub get_apache_config {
  my %config;

  my $sth = $dbh->prepare("SELECT serveradmin, servername, use_ssl, timeout, keepalivetimeout,
    min_servers, max_servers, start_servers, http_port, https_port, certificate_file, tls_certificate_data, tls_certificate_key, tls_certificate_chain FROM httpd_config");
  $sth->execute() or fatal_error("CANNOTEXECUTEQUERY", $dbh->errstr);

  return if ($sth->rows < 1);
  my $ref = $sth->fetchrow_hashref() or return;

  $config{'__TIMEOUT__'} = $ref->{'timeout'};
  $config{'__MINSERVERS__'} = $ref->{'min_servers'};
  $config{'__MAXSERVERS__'} = $ref->{'max_servers'};
  $config{'__STARTSERVERS__'} = $ref->{'start_servers'};
  $config{'__KEEPALIVETIMEOUT__'} = $ref->{'keepalivetimeout'};
  $config{'__HTTPPORT__'} = $ref->{'http_port'};
  $config{'__HTTPSPORT__'} = $ref->{'https_port'};
  $config{'__USESSL__'} = $ref->{'use_ssl'};
  $config{'__SERVERNAME__'} = $ref->{'servername'};
  $config{'__SERVERADMIN__'} = $ref->{'serveradmin'};
  $config{'__CERTFILE__'} = $ref->{'certificate_file'};
  $config{'tls_certificate_data'} = $ref->{'tls_certificate_data'};
  $config{'tls_certificate_key'} = $ref->{'tls_certificate_key'};
  $config{'tls_certificate_chain'} = $ref->{'tls_certificate_chain'};

  $sth->finish();
  return %config;
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

sub dump_certificate ($cert, $key, $chain) {
  my $path = "$SRCDIR/etc/apache/certs/certificate.pem";
  my $backup = "$SRCDIR/etc/apache/certs/default.pem";
  my $chainpath = "$SRCDIR/etc/apache/certs/certificate-chain.pem";

  if (!$cert || !$key || $cert =~ /^\s+$/ || $key =~ /^\s+$/) {
    my $cmd = "cp $backup $path";
    `$cmd`;
  } else {
    $cert =~ s/\r\n/\n/g;
    $key =~ s/\r\n/\n/g;
    if (open(my $FILE, ">", $path)) {
      print $FILE $cert."\n";
      print $FILE $key."\n";
      close $FILE;
    }
  }

  if ( $chain && $chain ne '' ) {
    if (open(my $FILE, ">", $chainpath)) {
      print $FILE $chain."\n";
      close $FILE;
    }
  }
  return;
}
