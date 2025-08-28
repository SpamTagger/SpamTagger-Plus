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

package SMTPAuthenticator::SQL;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib";
use DBI();

sub new ($server, $port, $params = {}) {
  my $usessl = 0;
  my $database_type = 'mysql';
  my $database = '';
  my $dbtable = '',
  my $dbuser = '',
  my $dbpass = '',
  my $loginfield = '',
  my $passfield  = '',
  my $crypt_type = 'crypt';
  my $dsn = '';

  my @fields = split /:/, $params;
  if ($fields[0] && $fields[0] =~ /^[01]$/) { $usessl = $fields[0]; }
  if ($fields[1]) { $database_type = $fields[1]; }
  if ($fields[2]) { $database = $fields[2]; }
  if ($fields[3]) { $dbtable = $fields[3]; }
  if ($fields[4]) { $dbuser = $fields[4]; }
  if ($fields[5]) { $dbpass = $fields[5]; }
  if ($fields[6]) { $loginfield = $fields[6]; }
  if ($fields[7]) { $passfield = $fields[7]; }
  if ($fields[10]) { $crypt_type = $fields[10]; }

  $port = 3306 if ($port < 1 );

  $dsn = "DBI:$database_type:database=$database;host=$server:$port";

  if ($server eq 'local') {
    require ReadConfig;
    my $conf = ReadConfig::get_instance();
    my $socket = $conf->get_option('VARDIR')."/run/mysql_slave/mysqld.sock";

    $dsn = "DBI:mysql:database=st_config;host=localhost;mysql_socket=$socket";
    $dbuser = 'spamtagger';
    $dbpass = $conf->get_option('MYSPAMTAGGERPWD');
    $dbtable = 'mysql_auth';
    $loginfield = 'username';
    $passfield = 'password';
  }

  my $this = {
    error_text => "",
    error_code => -1,
    server => $server,
    port => $port,
    usessl => $usessl,
    database_type => $database_type,
    database => $database,
    dbtable => $dbtable,
    dbuser => $dbuser,
    dbpass => $dbpass,
    loginfield => $loginfield,
    passfield => $passfield,
    crypt_type => $crypt_type,
    dsn => $dsn
  };
  $this->{$_} = $params->{$_} foreach (keys(%{$params}));

  bless $this, "SMTPAuthenticator::SQL";
  return $this;
}

sub authenticate ($this, $username, $password) {
  my $dbh = DBI->connect($this->{dsn}, $this->{dbuser}, $this->{dbpass}, {RaiseError => 0, PrintError => 0});
  unless ( $dbh ) {
    $this->{'error_code'} = 1;
    $this->{'error_text'} = 'Could not connect to SQL server';
    return 0;
  }

  my $system = SystemPref::create();
  my $domain = $system->get_pref('default_domain');
  $username =~ s/'//g;
  if ($username =~ m/(\S+)\@(\S+)/) {
    $domain = $2;
  }
  my $query = "SELECT ".$this->{passfield}." AS pass FROM ".$this->{dbtable}." WHERE ".$this->{loginfield}."='".$username."' AND domain='".$domain."'";

  my $sth = $dbh->prepare($query);
  unless ($sth) {
    $this->{'error_code'} = 2;
    $this->{'error_text'} = 'Could not prepare query';
    $dbh->disconnect() if ($dbh);
    return 0;
  }
  my $res = $sth->execute();
  my $ret = $sth->fetchrow_hashref();
  unless ($ret) {
    $this->{'error_code'} = 2;
    $this->{'error_text'} = "Bad username or password ($username)";
    $sth->finish();
    $dbh->disconnect() if ($dbh);
    return 0;
  }
  if ($ret->{pass}) {
    if (crypt ($password, $ret->{pass}) eq $ret->{pass}) {
      $sth->finish();
      $dbh->disconnect() if ($dbh);
      return 1;
    }
  }

  $this->{'error_code'} = 3;
  $this->{'error_text'} = "Bad username or password ($username)";

  $sth->finish();
  $dbh->disconnect() if ($dbh);
  return 0;
}

1;
