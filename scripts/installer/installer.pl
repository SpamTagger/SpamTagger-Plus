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

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/scripts/installer/';

use Module::Network();
use Module::Hostname();
use Module::Keyboard();
use Module::Timezone();
use Module::STInstaller();
use Module::Cluster();
use Module::RootPassword();
use DialogFactory();

my $d = DialogFactory->new('InLine');
my $dlg = $d->list_dialog();

my @basemenu = (
  'Keyboard configuration', 
  'Set root shell password', 
  'Set hostname', 
  'Network configuration', 
  'Timezone configuration', 
  'SpamTagger Plus configuration', 
  'Join existing cluster (optional)', 
  'Exit'
);
my $currentstep = 1;

while (do_menu()) {}

$dlg->clear();

exit 0;

sub do_menu {
  $dlg->build('SpamTagger Plus: base system configuration', \@basemenu, $currentstep, 1);

  my $res = $dlg->display();
  return 0 if $res eq 'Exit';

  if ($res eq 'Keyboard configuration') {
    my $keyb = Module::Keyboard->new();
    $keyb->run();
    $currentstep = 2;
    return 1;
  }

  if ($res eq 'Set root shell password') {
    my $pass = Module::RootPassword->new();
    $pass->run();
    $currentstep = 3;
    return 1;
  }

  if ($res eq 'Set hostname') {
    my $hostn = Module::Hostname->new();
    $hostn->run();
    $currentstep = 4;
    return 1;
  }

  if ($res eq 'Network configuration') {
    my $net = Module::Network->new();
    $net->run();
    $currentstep = 5;
    return 1;
  }

  if ($res eq 'Timezone configuration') {
    my $tz = Module::Timezone->new();
    $tz->run();
    $currentstep = 6;
    return 1;
  }

  if ($res eq 'SpamTagger Plus configuration') {
    my $stinstall = Module::STInstaller->new();
    my $ret = $stinstall->run();
    if ($ret == 0) {
      $currentstep = 7;
    } elsif ($ret == 1) {
      $currentstep = 4;
    }
    return 1;
  }

  if ($res eq 'Join existing cluster (optional)') {
    my $cluster = Module::Cluster->new();
    if ($cluster->run()) {
      $currentstep = 8;
    } else {
      $currentstep = 6;
    }
    return 1;
  }
  $dlg->clear();

  die "Invalid selection: $res\n";
}
