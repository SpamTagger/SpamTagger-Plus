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

package SMTPAuthenticator::Radius;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Authen::Radius;

sub new ($server, $port, $params = {}) {
  my $secret = '';
  my @fields = split /:/, $params;
  $secret = $fields[0] if ($fields[0]);

  $port = 1645 if ($port < 1 );
  my $this = {
    error_text => "",
    error_code => -1,
    server => $server,
    port => $port,
    secret => $secret,
  };
  $this->{$_} = $params->{$_} foreach (keys(%{$params}));

  bless $this, "SMTPAuthenticator::Radius";
  return $this;
}

sub authenticate ($this, $username, $password) {
  my $r = Authen::Radius->new(Host => $this->{server}.":".$this->{port}, Secret => $this->{secret});

  if ( $r && $r->check_pwd($username, $password) ) {
    $this->{'error_code'} = 0;
    $this->{'error_text'} = Authen::Radius::strerror;
    return 1;
  }

  $this->{'error_code'} =  Authen::Radius::get_error;
  $this->{'error_text'} = Authen::Radius::strerror;
  return 0;
}

1;
