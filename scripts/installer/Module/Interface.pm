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
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

package Module::Interface;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/scripts/installer/";
use DialogFactory();

sub new($class, $interface) {
  printf("Interface: $interface, Class: $class");

  my $this = {
    interface => $interface,
    ip => '192.168.1.101',
    mask => '',
    gateway => '',
    broadcast => '',
    dns => (),
  };

  return bless $this, $class;
}

sub dhcp($this) {
  my $str;

  $str = "allow-hotplug ".$this->{interface}."\n";
  $str .= "auto ".$this->{interface}."\n";
  $str .= "iface ".$this->{interface}." inet dhcp\n";

  return $str;
}

sub ask($this) {
  my $dfact = DialogFactory->new('InLine');
  my $dlg = $dfact->simple();
  $dlg->clear();
  my $title = "Configuring network interface (".$this->{interface}.")";
  print $title."\n";
  for (my $i=0; $i<length($title); $i++) {
    print "-";
  }
  print "\n\n";

  ##########
  ## get IP
  $dlg->build('Please enter the IP address', $this->{ip});
  my $ip = '';
  while( !is_ip($ip) ) {
    print "Bad address format, please type again.\n" if ! $ip eq "";
    $ip = $dlg->display();
  }
  $this->{ip} = $ip;

  my $mask = '255.255.255.0';
  if ( $this->{ip} =~ m/^(\d+)/ ) {
    my $init = $1;
    if ($init < 127 ) {
      $mask = '255.0.0.0';
    } elsif ($init < 192) {
      $mask = '255.255.0.0';
    }
  }

  ##########
  ## get mask
  $dlg->build('Please enter the network mask', $mask);
  my $lmask = '';
  while( !is_ip($lmask) ) {
    print "Bad address format, please type again.\n" if ! $lmask eq "";
    $lmask = $dlg->display();
  }
  $this->{mask} = $lmask;

  $this->compute_data();

  ##############
  ## get gateway
  $dlg->build('Please enter the default gateway', $this->{gateway});
  my $lgate = '';
  while( !is_ip($lgate) ) {
    print "Bad address format, please type again.\n" if ! $lgate eq "";
    $lgate = $dlg->display();
  }
  $this->{gateway} = $lgate;
  return;
}

sub get_gateway($this) {
  return $this->{gateway};
}

sub run($this) {
  print "Interface: ".$this->{interface}."\n";
  print "got ip: ".$this->{ip}."\n";
  print "got mask: ".$this->{mask}."\n";
  print "got gateway: ".$this->{gateway}."\n";
  print "got broadcast: ".$this->{broadcast}."\n";
  return;
}

sub get_config($this) {
  my $str;

  $str = "allow-hotplug ".$this->{interface}."\n";
  $str .= "auto ".$this->{interface}."\n";
  $str .= "iface ".$this->{interface}." inet static\n";
  $str .= "    address ".$this->{ip}."\n";
  $str .= "    netmask ".$this->{mask}."\n";
  $str .= "    gateway ".$this->{gateway}."\n";
  $str .= "    broadcast ".$this->{broadcast}."\n";

  return $str;
}

sub compute_data($this) {
  my @ipoct = split(/\./, $this->{ip});
  my @nmoct = split(/\./, $this->{mask});
  my @broct = ();
  my @gwoct = ();

  for (my $i = 0; $i < 4; $i++) {
    if ($nmoct[$i] == 255) {
      push(@gwoct, $ipoct[$i]);
      push(@broct, $ipoct[$i]);
    } else {
      if ($i == 3) {
        push(@gwoct, 1);
        push(@broct, 255);
      } else {
        push(@gwoct, 0);
        push(@broct, 0);
      }
    }
  }
  $this->{gateway} = join('.', @gwoct);
  $this->{broadcast} = join('.', @broct);
  return;
}

########
## static functions
sub is_ip($ip) {
  if ( $ip =~ m/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ ) {
    return 0 if $1 < 0 || $1 > 255;
    return 0 if $2 < 0 || $2 > 255;
    return 0 if $3 < 0 || $3 > 255;
    return 0 if $4 < 0 || $4 > 255;
    return 1;
  }
  return 0;
}

1;
