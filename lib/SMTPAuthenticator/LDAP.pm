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

package SMTPAuthenticator::LDAP;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Net::LDAP;

my @mailattributes = ('mail', 'maildrop', 'mailAlternateAddress', 'mailalternateaddress', 'proxyaddresses', 'proxyAddresses', 'oldinternetaddress', 'oldInternetAddress', 'cn', 'userPrincipalName');

sub new ($server, $port, $params) {
  my $this = {
    error_text => "",
    error_code => -1,
    server => '',
    port => 389,
    use_ssl => 0,
    base => '',
    attribute => 'uid',
    binduser => '',
    bindpassword => '',
    version => 3
  };

  $this->{server} = $server;
  $this->{port} = $port if ($port > 0 );
  my @fields = split /:/, $params;
  $this->{use_ssl} = $fields[4]       if ($fields[4] && $fields[4] =~ /^[01]$/);
  $this->{base} = $fields[0]          if ($fields[0]);
  $this->{attribute} = $fields[1]     if ($fields[1]);
  $this->{binduser} = $fields[2]      if ($fields[2]);
  $this->{bindpassword} = $fields[3]  if ($fields[3]);
  $this->{bindpassword} =~ s/__C__/:/ if ($fields[3]);
  $this->{version} = 2                if ($fields[5] && $fields[5] == 2);

  bless $this, "SMTPAuthenticator::LDAP";
  return $this;
}

sub authenticate ($this, $username, $password) {
  my $scheme = 'ldap';
  if ($this->{use_ssl} > 0) {
    $scheme = 'ldaps';
  }
  my $ldap = Net::LDAP->new ( $this->{server}, port=>$this->{port}, scheme=>$scheme, timeout=>30, debug=>0 );

  unless ($ldap) {
    $this->{'error_text'} = "Cannot contact LDAP/AD server at $scheme://".$this->{server}.":".$this->{port};
    return 0;
  }

  my $userdn = $this->get_dn($username);
  return 0 if ($userdn eq '');

  my $mesg = $ldap->bind (
    $userdn,
    password => $password,
    version => $this->{version}
  );

  $this->{'error_code'} = $mesg->code;
  $this->{'error_text'} = $mesg->error_text;
  return 1 if ($mesg->code == 0);
  return 0;
}

sub get_dn ($this, $username) {
  my $scheme = 'ldap';
  $scheme = 'ldaps' if ($this->{use_ssl} > 0);

  my $ldap = Net::LDAP->new ( $this->{server}, port=>$this->{port}, scheme=>$scheme, timeout=>30, debug=>0 );
  my $mesg;
  if (! $this->{binduser} eq '') {
    $mesg = $ldap->bind($this->{binduser}, password => $this->{bindpassword}, version => $this->{version});
  } else {
    $mesg = $ldap->bind ;
  }
  if ( $mesg->code ) {
    $this->{'error_text'} = "Could not search for user DN (bind error)";
    return '';
  }
  $mesg = $ldap->search (base => $this->{base}, scope => 'sub', filter => "(".$this->{attribute}."=$username)");
  if ( $mesg->code ) {
    $this->{'error_text'} = "Could not search for user DN (search error)";
    return '';
  }
  my $numfound = $mesg->count ;
  my $dn="" ;
  if ($numfound) {
     my $entry = $mesg->entry(0);
     $dn = $entry->dn ;
  } else {
    $this->{'error_text'} = "No such user ($username)";
  }
  $ldap->unbind;   # take down session
  return $dn ;
}

sub fetch_linked_addresses_from_email ($this, $email) {
  my $filter = '(|';
  foreach my $att (@mailattributes) {
    $filter .= '('.$att.'='.$email.')('.$att.'='.'smtp:'.$email.')';
  }
  $filter .= ')';
  return $this->fetch_linked_addresses_from_filter($filter);
}

sub fetch_linked_addresses_from_username ($this, $username) {
  my $filter = $this->{attribute}."=".$username;
  return $this->fetch_linked_addresses_from_filter($filter);
}

sub fetch_linked_addresses_from_filter ($this, $filter) {
  my @addresses;

  my $scheme = 'ldap';
  $scheme = 'ldaps' if ($this->{use_ssl} > 0);

  my $ldap = Net::LDAP->new ( $this->{server}, port=>$this->{port}, scheme=>$scheme, timeout=>30, debug=>0 );
  my $mesg;
  if (!$ldap) {
    $mesg = 'Cannot open LDAP session';
    return @addresses;
  }
  if (! $this->{binduser} eq '') {
    $mesg = $ldap->bind($this->{binduser}, password => $this->{bindpassword}, version => $this->{version});
  } else {
    $mesg = $ldap->bind ;
  }
  if ( $mesg->code ) {
    $this->{'error_text'} = "Could not bind";
    return @addresses;
  }
  $mesg = $ldap->search (base => $this->{base}, scope => 'sub', filter => $filter);
  if ( $mesg->code ) {
     $this->{'error_text'} = "Could not search";
   return @addresses;
  }
  my $numfound = $mesg->count ;
  my $dn="" ;
  if ($numfound) {
    my $entry = $mesg->entry(0);
    foreach my $att (@mailattributes) {
      foreach my $add ($entry->get_value($att)) {
        if ($add =~ m/\@/) {
          $add =~ s/^smtp\://gi;
          push @addresses, lc($add);
        }
      }
    }
  }
  $ldap->unbind;   # take down session
  return @addresses;
}

1;
