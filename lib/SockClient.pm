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

package  SockClient;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use IO::Socket qw( SOCK_STREAM );
use IO::Select();
use Time::HiRes qw(setitimer time);

sub new ($class, $spec_this = {}) {
  my $this = {
    timeout => 5,
    socketpath => '/tmp/'.$class,
  };

  # add specific options of child object
  $this->{$_} = $spec_this->{$_} foreach (keys(%{$spec_this}));

  bless $this, $class;
  return $this;
}

sub sock_connect ($this) {
  ## untaint some values
  $this->{socketpath} = $1 if ($this->{socketpath} =~ m/^(\S+)/);
  $this->{timeout} = $1 if ($this->{timeout} =~ m/^(\d+)$/);

  $this->{socket} = IO::Socket::UNIX->new(
    Peer    => $this->{socketpath},
    Type    => SOCK_STREAM,
    Timeout => $this->{timeout}
  ) or return 0;

  return 1;
}

sub query ($this, $query) {
  my $sent = 0;
  my $tries = 1;

  $this->sock_connect() or return '_NOSERVER';
  my $sock = $this->{socket};

  $sock->send($query) or return '_NOSERVER';
  $sock->flush();

  my $data = '';
  my $rv;

  my $read_set = IO::Select->new();
  $read_set->add($sock);
  my ($r_ready, $w_ready, $error) =  IO::Select->select($read_set, undef, undef, $this->{timeout});

  foreach my $s (@$r_ready) {
    my $buf;
    my $buft;
    while(  my $ret = $s->recv($buft, 1024, 0) ) {
      if (defined($buft)) {
        $buf .= $buft;
      } else {
        $read_set->remove($sock);
        close($sock);
        return '_CLOSED';
      }
    }
    close($sock);
    return $buf;
  }
  return '_TIMEOUT';
}

1;
