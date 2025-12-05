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

package Module::Timezone;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use File::Basename qw( basename );
use lib "/usr/spamtagger/scripts/installer/";
use DialogFactory();

sub new($class) {
  my $this = {
    dlg => '',
    mapdir => '/usr/share/zoneinfo/'
  };
  return bless $this, $class;
}

sub run($this) {
  my $dfact = DialogFactory->new('InLine');
  $this->{dlg} = $dfact->list();

  my $relative = '';
  while (1) {
    my @dlglist = map { basename($_) } glob($this->{mapdir}.$relative."/[A-Z]*");

    $this->{dlg}->build('Choose your '.($relative?'closest city/country':'continent/region'), \@dlglist, 1, 1);
    $relative .= $this->{dlg}->display();
    if ( !-e $this->{mapdir} ) {
      die("Invalid Timezone selection: $relative\n");
    } elsif ( -f $this->{mapdir}.$relative ) {
      last;
    } else {
      $relative .= '/';
    }
  }

  my $cmd = "echo '$relative' > /etc/timezone";
  `$cmd`;
  `rm /etc/localtime 2>&1 > /dev/null`;
  $cmd = "ln -s $this->{mapdir}$relative  /etc/localtime";
  `$cmd`;
  return;
}

sub dolist($this, $dir, $parent) {
  return $dir unless -d $dir;

  my @dlglist;
  my $DIR;
  opendir($DIR, $dir) or return $dir;
  while(my $entry = readdir($DIR)) {
    next if $entry =~ m/\./;
    if ( -d "$dir/$entry" || -f "$dir/$entry") {
      push @dlglist, $entry;
    }
  }
  close($DIR);
  my $dlg = $this->{dlg};
  $dlg->build('Make your choice ('.$parent.')', \@dlglist, 1);
  my $res = $dlg->display();
  return $this->dolist($dir."/".$res, $res);
}

1;
