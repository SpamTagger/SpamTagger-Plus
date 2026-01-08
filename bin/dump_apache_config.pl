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
#
#   This script will dump the apache config file with the configuration
#   settings found in the database.
#
#   Usage:
#           dump_apache_config.pl


use v5.40;
use strict;
use warnings;
use utf8;
use Carp qw( confess );

our ($SRCDIR, $VARDIR, $HOSTID, $MYSPAMTAGGERPWD);
BEGIN {
    if ($0 =~ m/(\S*)\/\S+.pl$/) {
        my $path = $1."/../lib";
        unshift (@INC, $path);
    }
    require ReadConfig;
    my $conf = ReadConfig::get_instance();
    $SRCDIR = $conf->get_option('SRCDIR');
    $VARDIR = $conf->get_option('VARDIR');
    $HOSTID = $conf->get_option('HOSTID');
    $MYSPAMTAGGERPWD = $conf->get_option('MYSPAMTAGGERPWD');
    unshift(@INC, $SRCDIR."/lib");
}

require DB;
use STUtils qw( open_as rmrf );
use File::Touch qw( touch );

our $DEBUG = 1;
our $uid = getpwnam('www-data');
our $gid = getgrnam('spamtagger');

my $lasterror = "";

# Delete old session files
mkdir('/tmp/php_sessions') unless (-d '/tmp/php_sessions');
unlink($_) foreach (glob('/tmp/php_sessions/*'));
unlink('/tmp/php_sessions.sqlite') if (-e '/tmp/php_sessions.sqlite');
unlink($_) foreach (glob("$VARDIR/www/stats/*.png"));

# Create necessary dirs/files if they don't exist
touch('/tmp/php_sessions.sqlite') || print("Failed to create /tmp/php_sessions.sqlite\n");
mkdir('/var/spamtagger/log/apache') unless (-d '/var/spamtagger/log/apache');
mkdir('/var/spamtagger/www') unless (-d '/var/spamtagger/www');
mkdir('/var/spamtagger/www/mrtg') unless (-d '/var/spamtagger/www/mrtg');
mkdir('/var/spamtagger/www/stats') unless (-d '/var/spamtagger/www/stats');
mkdir('/var/spamtagger/run/apache2') unless (-d '/var/spamtagger/run/apache2');

# Set proper permissions
chown($uid, $gid,
    '/tmp/php_sessions/',
    '/tmp/php_sessions.sqlite',
    '/var/spamtagger/log/apache',
    '/var/spamtagger/www/',
    glob('/var/spamtagger/www/*'),
    glob('/var/spamtagger/www/mrtg/*'),
    glob('/var/spamtagger/www/stats/*'),
    '/var/spamtagger/run/ssl.cache',
    '/var/spamtagger/run/apache2',
    glob('/var/spamtagger/run/apache2/*'),
    '/etc/apache2',
    glob('/etc/apache2/*'),
    glob($VARDIR.'/log/apache/*'),
    glob($SRCDIR.'/etc/apache/sites-available/*'),
    glob($SRCDIR.'/www/guis/admin/public/tmp/*'),
);

# Fix symlinks if broken
my %links = (
    '/etc/apparmor.d/spamtagger' => ${SRCDIR}.'/etc/apparmor',
    '/etc/apache2' => ${SRCDIR}.'/etc/apache',
    ${SRCDIR}.'/etc/apache2/modules' => '/usr/lib/apache2/modules',
);
foreach my $link (keys(%links)) {
    if (-e $link) {
        if (-l $link) {
            next if (readlink($link) eq $links{$link});
	    unlink($link);
        } else {
            rmrf($link);
        }
    }
    symlink($links{$link}, $link);
}

# Reload AppArmor rules
`apparmor_parser -r ${SRCDIR}/etc/apparmor.d/apache` if ( -d '/sys/kernel/security/apparmor' );

# Configure sudoer permissions if they are not already
mkdir '/etc/sudoers.d' unless (-d '/etc/sudoers.d');
if (open(my $fh, '>', '/etc/sudoers.d/apache')) {
    print $fh "
User_Alias  APACHE = spamtagger
Runas_Alias EXIM = spamtagger
Cmnd_Alias  CHECKSPOOLS = $SRCDIR/bin/check_spools.sh
Cmnd_Alias  GETSTATUS = $SRCDIR/bin/get_status.pl -s

APACHE      * = (ROOT) NOPASSWD: SETPINDB
APACHE      * = (EXIM) NOPASSWD: CHECKSPOOLS
APACHE      * = (ROOT) NOPASSWD: GETSTATUS
";
}

# SystemD auth causes timeouts
`sed -iP '/^session.*pam_systemd.so/d' /etc/pam.d/common-session`;

# Dump configuration
our $dbh;
$dbh = DB->db_connect('replica', 'st_config');

my %sys_conf = get_system_config() or fatal_error("NOSYSTEMCONFIGURATIONFOUND", "no record found for system configuration");

my %apache_conf;
%apache_conf = get_apache_config() or fatal_error("NOAPACHECONFIGURATIONFOUND", "no apache configuration found");

dump_apache_file("${SRCDIR}/etc/apache/apache2.conf_template", "${SRCDIR}/etc/apache/apache2.conf") or fatal_error("CANNOTDUMPAPACHEFILE", $lasterror);

dump_apache_file("${SRCDIR}/etc/apache/sites-available/spamtagger.conf_template", "${SRCDIR}/etc/apache/sites-enabled/spamtagger.conf") or fatal_error("CANNOTDUMPAPACHEFILE", $lasterror);
dump_apache_file("${SRCDIR}/etc/apache/sites-available/soap.conf_template", "${SRCDIR}/etc/apache/sites-enabled/soap.conf") or fatal_error("CANNOTDUMPAPACHEFILE", $lasterror);

# TODO: This needs to be dumped to a writable directory instead. This may be tricky since the document root is in the non-writable area. We may need to change the SOAP document root or symlink.
dump_soap_wsdl($sys_conf{'HOST'}, $apache_conf{'__USESSL__'}) or fatal_error("CANNOTDUMPWSDLFILE", $lasterror);

dump_certificate(${SRCDIR},$apache_conf{'tls_certificate_data'}, $apache_conf{'tls_certificate_key'}, $apache_conf{'tls_certificate_chain'});

#############################
sub dump_apache_file($template_file, $target_file)
{
    my ($TEMPLATE, $TARGET);
    unless ( $TEMPLATE = ${open_as($template_file, '<')} ) {
        confess("Cannot open template file: $template_file");
    }
    unless ( $TARGET = ${open_as($target_file)} ) {
        close $template_file;
        confess("Cannot open target file: $target_file");
    }

    my $inssl = 0;
    while(<$TEMPLATE>) {
        my $line = $_;

        $line =~ s/__VARDIR__/${VARDIR}/g;
        $line =~ s/__SRCDIR__/${SRCDIR}/g;
        $line =~ s/__DBPASSWD__/${MYSPAMTAGGERPWD}/g;

        foreach my $key (keys %sys_conf) {
            $line =~ s/$key/$sys_conf{$key}/g;
        }
        foreach my $key (keys %apache_conf) {
            $line =~ s/$key/$apache_conf{$key}/g;
        }

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

        if ( (! $inssl) || ($apache_conf{'__USESSL__'} =~ /true/) ) {
            print $TARGET $line;
        }
    }

    close $TEMPLATE;
    close $TARGET;
    chown($uid, $gid, $target_file);

    return 1;
}

sub dump_soap_wsdl($host, $use_ssl)
{

    my $template_file = "${SRCDIR}/www/soap/htdocs/spamtagger.wsdl_template";
    my $target_file = "${SRCDIR}/www/soap/htdocs/spamtagger.wsdl";

    my $protocol = 'http';
    $protocol .= 's' if ($use_ssl);

    my ($TEMPLATE, $TARGET);
    if ( !open($TEMPLATE, '<', $template_file) ) {
        $lasterror = "Cannot open template file: $template_file";
        return 0;
    }
    if ( !open($TARGET, '>', $target_file) ) {
        $lasterror = "Cannot open target file: $target_file";
        close $template_file;
        return 0;
    }

    my $inssl = 0;
    while(<$TEMPLATE>) {
        my $line = $_;

        $line =~ s/__HOST__/$host/g;
        $line =~ s/__PROTOCOL__/$protocol/g;
        print $TARGET $line;
    }

    close $TEMPLATE;
    close $TARGET;
    chown($uid, $gid, $target_file);

    return 1;
}

#############################
sub get_system_config()
{
    my %config;

    my @sys_conf = $dbh->get_list_of_hash("SELECT hostname, default_domain, sysadmin, clientid FROM system_conf");

    return unless (@sys_conf);

    $config{'__PRIMARY_HOSTNAME__'} = $sys_conf[0]->{'hostname'};
    $config{'__QUALIFY_DOMAIN__'} = $sys_conf[0]->{'default_domain'};
    $config{'__QUALIFY_RECIPIENT__'} = $sys_conf[0]->{'sysadmin'};
    $config{'__CLIENTID__'} = $sys_conf[0]->{'clientid'};

    my @replica = $dbh->get_list_of_hash("SELECT hostname FROM replica WHERE id=".$HOSTID);
    return unless (@replica);

    $config{'HOST'} = $replica[0]->{'hostname'};

    return %config;
}

#############################
sub get_apache_config()
{
    my %config;

    my @http = $dbh->get_list_of_hash("SELECT serveradmin, servername, use_ssl, timeout, keepalivetimeout,
        min_servers, max_servers, start_servers, http_port, https_port, certificate_file, tls_certificate_data, tls_certificate_key, tls_certificate_chain FROM httpd_config");
    return unless (@http);

    $config{'__TIMEOUT__'} = $http[0]->{'timeout'};
    $config{'__MINSERVERS__'} = $http[0]->{'min_servers'};
    $config{'__MAXSERVERS__'} = $http[0]->{'max_servers'};
    $config{'__STARTSERVERS__'} = $http[0]->{'start_servers'};
    $config{'__KEEPALIVETIMEOUT__'} = $http[0]->{'keepalivetimeout'};
    $config{'__HTTPPORT__'} = 8080;
    $config{'__HTTPSPORT__'} = 4443;
    $config{'__USESSL__'} = $http[0]->{'use_ssl'};
    $config{'__SERVERNAME__'} = $http[0]->{'servername'};
    $config{'__SERVERADMIN__'} = $http[0]->{'serveradmin'} || "root\@$http[0]->{'servername'}";
    $config{'__CERTFILE__'} = $http[0]->{'certificate_file'};
    $config{'tls_certificate_data'} = $http[0]->{'tls_certificate_data'};
    $config{'tls_certificate_key'} = $http[0]->{'tls_certificate_key'};
    $config{'tls_certificate_chain'} = $http[0]->{'tls_certificate_chain'};
    $config{'__PHP_VERSION__'} = `php --version | head -n 1 | sed -r 's/PHP ([0-9]*\.[0-9]*).*/\1/'`;
    $config{'__PHP_VERSION__'} = '8.4' unless $config{'__PHP_VERSION__'} =~ m/^([0-9]*\.[0-9]*).*$/;

    return %config;
}

#############################
sub fatal_error($msg,$full)
{
    print $msg . ($DEBUG ? "\nFull information: $full \n" : "\n");
    exit(1);
}

#############################
sub print_usage
{
    print "Bad usage: dump_exim_config.pl [stage-id]\n\twhere stage-id is an integer between 0 and 4 (0 or null for all).\n";
    exit(0);
}

sub dump_certificate($srcdir,$cert,$key,$chain)
{
    my $path = $srcdir."/etc/apache/certs/certificate.pem";
    my $backup = $srcdir."/etc/apache/certs/default.pem";
    my $chainpath = $srcdir."/etc/apache/certs/certificate-chain.pem";

    if (!$cert || !$key || $cert =~ /^\s+$/ || $key =~ /^\s+$/) {
        my $cmd = "cp $backup $path";
        `$cmd`;
    } else {
        $cert =~ s/\r\n/\n/g;
        $key =~ s/\r\n/\n/g;
        if ( open(my $FILE, '>', $path)) {
            print $FILE $cert."\n";
            print $FILE $key."\n";
            close $FILE;
        }
    }

    if ( $chain && $chain ne '' ) {
        if ( open(my $FILE, '>', $chainpath)) {
            print $FILE $chain."\n";
            close $FILE;
        }
    }
    chown($uid, $gid, $path, $backup, $chainpath);
    return;
}
