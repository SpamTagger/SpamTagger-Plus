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

# TODO: This doesn't appear to be used by anything.
package UDPClient;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use IO::Socket qw( close );
use IO::Select();

sub new ($class, %spec_this) {
  my $this = {
    port => -1,
    timeout => 5,
    socket => '',
  };

  # add specific options of child object
  foreach my $sk (keys %spec_this) {
     $this->{$sk} = $spec_this{$sk};
  }

  bless $this, $class;
  return $this;
}

sub udp_connect ($this) {
  $this->{socket} = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => $this->{port},
    Proto     => 'udp',
    Timeout => $this->{timeout}
  ) or die "Couldn't be an udp server on port ".$this->{port}." : $@\n";

  return 0;
}

sub query ($this, $query) {
  my $sent = 0;
  my $tries = 1;
  while ($tries < 2 && ! $sent) {
    $tries++;
    my $write_set = IO::Select->new();
    $write_set->add($this->{socket});
    my ($r_ready, $w_ready, $error) =  IO::Select->select(undef, $write_set, undef, $this->{timeout});
    foreach my $sock (@$w_ready) {
      $sock->send($query."\n");
      $write_set->remove($sock);
      $sent = 1;
    }
    if (! $sent) {
      if ($tries < 2) {
        $this->udp_connect();
        next;
      }
      return '_NOSOCKET';
    }
  }

  my $msg;

  my $read_set = IO::Select->new();
  $read_set->add($this->{socket});

  my ($r_ready, $w_ready, $error) =  IO::Select->select($read_set, undef, undef, $this->{timeout});
  foreach my $sock (@$r_ready) {
    my $buf = <$sock>;
    if ($buf) {
      chop($buf);
      return $buf;
    } else {
      $read_set->remove($sock);
      return "_NOSERVER";
    }
  }
  return '_TIMEOUT';
}

sub ping ($this) {
  # TODO: Incorrect return? return 1 if socket is found? Currently this always returns 0.
  return 0 unless $this->{socket};
  return 0;
}

sub udp_close ($this) {
  close($this->{socket});
  return 1;
}

1;
