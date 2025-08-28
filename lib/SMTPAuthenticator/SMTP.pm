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
#

package SMTPAuthenticator::SMTP;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Net::SMTP_auth;

sub new ($server, $port, $params = {}) {
  $port = 25 if ($port < 1 );
  my $this = {
    error_text => "",
    error_code => -1,
    server => $server,
    port => $port
  };
  $this->{$_} = $params->{$_} foreach (keys(%{$params}));

  bless $this, "SMTPAuthenticator::SMTP";
  return $this;
}

sub authenticate ($this, $username, $password) {
  unless ($smtp = Net::SMTP_auth->new($this->{server}.":".$this->{port})) {
    $this->{'error_code'} = 0;
    $this->{'error_text'} = 'Cannot connect to server: '.$this->{server}.' on port '.$this->{port};
    return 0;
  }

  my $auth_type = 'LOGIN';
  my @auths = split('\s', $smtp->auth_types());
  $auth_type = shift(@auths)  if (@auths);

  if ($smtp->auth($auth_type, $username, $password)) {
    $this->{'error_code'} = 0;
    $this->{'error_text'} = '';
    $smtp->quit();
    return 1;
  }
  $this->{'error_code'} = 1;
  $this->{'error_text'} = 'Authentication failed';
  $smtp->quit();
  return 0;
}

1;
