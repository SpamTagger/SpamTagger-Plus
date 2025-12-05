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

package Module::Resolver;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/scripts/installer/";
use DialogFactory();

sub new($class, $dhcp=undef) {
  my $this = {
    domain => '',
    dns => {},
    dnss => '',
    dhcp => $dhcp
  };

  return bless $this, $class;
}

sub set_dns($this, $pos, $value) {
  $this->{dns}{$pos} = $value;
  return;
}

sub ask($this) {
  my $dfact = DialogFactory->new('InLine');
  my $dlg = $dfact->simple();
  print "Configuring resolver\n";
  print "--------------------\n\n";

  #############
  ## get dns
  my %dnsname = (1 => 'primary', 2 => 'secondary', 3 => 'tertiary');
  for (my $n=1; $n<4; $n++) {
    my $select;
    if ($this->{dhcp}) {
      $select = 'DHCP';
    } else {
      $select = $this->{dns}{$n};
    }
    $dlg->build('Please enter a '.$dnsname{$n}.' DNS server', $select);
    my $ldns = 'none';
    while( !Module::Interface::is_ip($ldns)  && (! $ldns eq '' )) {
      print "Bad address format, please type again.\n" if  ! $ldns eq 'none';
      $ldns = $dlg->display();
      if ($ldns eq 'DHCP') {
        $ldns = 0;
        last;
      }
      last unless ($ldns);
    }
    $this->{dns}{$n} = $ldns if ($ldns);
    last unless $ldns;
  }

  ##############
  ## get domain
  $dlg->build('Please enter the DNS search domain name', $this->{domain});
  my $dom = ' none ';
  while( !Module::Resolver::is_domain($dom)  && (! $dom eq '' )) {
    $dom = $dlg->display();
  }
  $this->{domain} = $dom;

  #################
  ## set dns string
  my $dnss = "";
  foreach my $dns (sort keys %{$this->{dns}}) {
    $dnss .= " ".$this->{dns}{$dns};
  }
  $dnss =~ s/^ //;
  $this->{dnss} = $dnss;
  return;
}

sub run($this) {
  my $dnss = "";
  foreach my $dns (sort keys %{$this->{dns}}) {
    $dnss .= " ".$this->{dns}{$dns};
  }
  $dnss =~ s/^ //;
  $this->{dnss} = $dnss;
  print "got dns: ".$this->{dnss}."\n";
  print "got domain: ".$this->{domain}."\n";
  return;
}

sub get_config($this) {
  my $str = "\n";
  foreach my $dns (sort keys %{$this->{dns}}) {
    next if $this->{dns}{$dns} eq '';
    $str .= "nameserver ".$this->{dns}{$dns}."\n";
  }

  if (! $this->{domain} eq '') {
    $str .= "search ".$this->{domain}."\n";
  }

  return $str;
}

sub is_domain($domain) {
  return 1 if ($domain =~ m/^[-a-zA-Z0-9_.]+$/);
  return 0;
}

1;
