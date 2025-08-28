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

package SMTPAuthenticator;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use SystemPref();
use Domain();
use ReadConfig();
use DBD::SQLite();
use Net::LDAP();
use Digest::MD5 qw(md5_hex);
use Time::HiRes qw(gettimeofday tv_interval);

sub new ($class, $username) {
  my $domainname = '';
  my $user = '';
  my $domain;
  my $authorized = 1;
  my $cachefile = '';

  # get domain
  if ($username =~ m/^(\S+)\@(\S+)$/) {
    $user = $1;
    $domainname = $2;
  }
  if ($domainname eq "") {
    my $system = SystemPref->new();
    $domainname = $system->get_pref('default_domain');
    $user = $username;
  }
  $domain = Domain->new($domainname);
  return unless ($domain);

  my $allowed = $domain->get_pref('allow_smtp_auth');
  $authorized = 0 unless ($allowed);

  my $conf = ReadConfig::get_instance();
  my $cachepath = $conf->get_option('VARDIR')."/spool/tmp/exim_stage1/auth_cache/";
  if (! -d $cachepath) {
    ::Auth_log('creating cache directory '.$cachepath);
    mkdir $cachepath;
  }
  $cachefile = $cachepath.'/'.$domainname.".db";

  # get username
  my $realusername = $user.'@'.$domainname;
  my $userformat = $domain->get_pref('auth_modif');
  $realusername = $user if ($userformat eq 'username_only');
  $realusername = $user.'%'.$domainname if ($userformat eq 'percent_add');

  # get auth server, port and params
  my $serverstr =  $domain->get_pref('auth_server');
  my $server = $serverstr;
  my $port = 0;
  if ($serverstr =~ /^(\S+):(\d+)$/) {
    $server = $1;
    $port = $2;
  }
  my $authparam = $domain->get_pref('auth_param');

  # get auth type
  my $authtype = $domain->get_pref('auth_type');
  my $auth;
  if ($authtype eq 'ldap') {
    require SMTPAuthenticator::LDAP;
    $auth = SMTPAuthenticator::LDAP->new($server, $port, $authparam);
  } elsif ($authtype eq 'pop3') {
    require SMTPAuthenticator::POP3;
    $auth = SMTPAuthenticator::POP3->new($server, $port, $authparam);
  } elsif ($authtype eq 'imap') {
    require SMTPAuthenticator::IMAP;
    $auth = SMTPAuthenticator::IMAP->new($server, $port, $authparam);
  } elsif ($authtype eq 'smtp') {
    require SMTPAuthenticator::SMTP;
    $auth = SMTPAuthenticator::SMTP->new($server, $port, $authparam);
  } elsif ($authtype eq 'radius') {
    require SMTPAuthenticator::Radius;
    $auth = SMTPAuthenticator::Radius->new($server, $port, $authparam);
  } elsif ($authtype eq 'local') {
    require SMTPAuthenticator::SQL;
    $auth = SMTPAuthenticator::SQL->new('local', 0, '');
  } elsif ($authtype eq 'sql') {
    require SMTPAuthenticator::SQL;
    $auth = SMTPAuthenticator::SQL->new($server, $port, $authparam);
  }

  unless ($auth) {
    require SMTPAuthenticator::NoAuth;
    $auth = SMTPAuthenticator::NoAuth->new('', '','');
  }

  my $this = {
    username => $realusername,
    domain => $domain,
    auth => $auth,
    authorized => $authorized,
    cachefile => $cachefile
  };

  return bless $this, $class;
}

sub authenticate ($this, $password, $ip) {
  if ($this->{authorized}) {

    my $create_cache_record = 0;
    my $cachedb = undef;
    my $cachetime = $this->{domain}->get_pref('smtp_auth_cachetime');
    if ($cachetime > 0) {
      my $present = 0;
      $present = 1 if (-f $this->{cachefile});
      $cachedb = DBI->connect("dbi:SQLite:".$this->{cachefile},"","",{PrintError=>0,InactiveDestroy=>1});
      if (!$present) {
        ## create database
        $cachedb->do("CREATE TABLE cache (username TEXT, domain TEXT, password TEXT, count INTEGER, last TIMESTAMP, first TIMESTAMP)");
        $cachedb->do("CREATE UNIQUE INDEX account_uniq ON cache(username, domain)");
        $cachedb->do("CREATE INDEX last_seen_idx ON cache(last)");
        $cachedb->do("CREATE INDEX first_seen_idx ON cache(first)");
      }

      ## check for entry
      my $sql = "SELECT password, count, last, first FROM cache WHERE username=? and domain=? and password=?";
      my $username_hash = md5_hex($this->{username});
      my $domain_hash = md5_hex($this->{domain}->{name});
      my $pass_hash = md5_hex($password);
      my $res = $cachedb->selectrow_hashref($sql,undef,$username_hash, $domain_hash, $pass_hash);
      if (defined($res)) {
        ## first check expiracy
        my $delta = time - $res->{first};
        if ($delta <= $cachetime) {
          ::Auth_log("Authentication passed for user ".$this->{username}." on domain ".$this->{domain}->{name}." [$ip] (cached)");
          return 1;
        } else {
          $sql = "DELETE FROM cache WHERE username=? and domain=?";
          my $sth = $cachedb->prepare($sql);
          $sth->execute($username_hash, $domain_hash);
          ::Auth_log("Record cache expired for user ".$this->{username}." on domain ".$this->{domain}->{name}." [$ip], deleted and proceeding to real authentication.");
          $create_cache_record = 1;
        }
      } else {
        $create_cache_record = 1;
      }
    }

    my $start_time = [gettimeofday];
    if ($this->{auth}->authenticate($this->{username}, $password)) {

      my $interval = tv_interval( $start_time );
      my $time     = ( int( $interval * 10000 ) / 10000 );

      if ($cachetime > 0 && $cachedb) {
        my $username_hash = md5_hex($this->{username});
        my $domain_hash = md5_hex($this->{domain}->{name});
        my $pass_hash = md5_hex($password);
        my $now = time;
        if ($create_cache_record) {
          my $sql = "INSERT INTO cache (username, domain, password, last, first) VALUES(?,?,?,?,?)";
          my $sth = $cachedb->prepare($sql);
          $sth->execute($username_hash, $domain_hash, $pass_hash, $now, $now);
        } else {
          my $sql = "UPDATE cache SET last=strftime('%s','now') WHERE username=? and domain=?";
          my $sth = $cachedb->prepare($sql);
          $sth->execute($username_hash, $domain_hash);
        }
      }
      ::Auth_log("Authentication passed for user ".$this->{username}." on domain ".$this->{domain}->{name}." [$ip] in $time s.");
      return 1;
    }
    my $interval = tv_interval( $start_time );
    my $time     = ( int( $interval * 10000 ) / 10000 );
    my $error = $this->{auth}->{error_text};
    chop($error);
    ::Auth_log("Authentication failed for user ".$this->{username}." on domain ".$this->{domain}->{name}." ($error) [$ip] in $time s.");
    return 0;
  }
  $this->{auth}->{error_text} = 'Authentication not allowed for this domain';
  ::Auth_log("Authentication not allowed for the domain ".$this->{domain}->{name});
  return 0;
}

sub get_error_text ($this) {
  my $msg = $this->{auth}->{error_text};
  chomp($msg);
  return $msg;
}

1;
