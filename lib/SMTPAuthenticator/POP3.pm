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

package SMTPAuthenticator::POP3;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use Mail::POP3Client;

sub new ($server, $port, $params = {}) {
  my $use_ssl = 0;
  $use_ssl = $params if ($params =~ /^[01]$/);
  $port = 110 if ($port < 1 );

  my $this = {
    error_text => "",
    error_code => -1,
    server => $server,
    port => $port,
    use_ssl => $use_ssl
  };
  $this->{$_} = $params->{$_} foreach (keys(%{$params}));

  bless $this, "SMTPAuthenticator::POP3";
  return $this;
}

sub authenticate ($this, $username, $password) {
  my $pop = Mail::POP3Client->new(
    HOST     => $this->{server},
    PORT     => $this->{port},
    USESSL   => $this->{use_ssl},
  );

  $pop->User( $username );
  $pop->Pass( $password );
  my $code = $pop->Connect();

  if ($code > 0) {
    $this->{'error_code'} = 0;
    $this->{'error_text'} = "";
    return 1;
  }
  $pop->Message();

  $this->{'error_code'} = $code;
  $this->{'error_text'} = $pop->Message();
  return 0;
}

1;
