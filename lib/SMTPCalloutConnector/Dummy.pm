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

package          SMTPCalloutConnector::Dummy;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

sub new ($class, $params = {}) {
  my $this = {
    'last_message' => '',
    'useable' => 1,
    'default_on_error' => 1 ## we accept in case of any failure, to avoid false positives
  };
  $this->{$_} = $params->{$_} foreach (keys(%{$params}));

  bless $this, $class;
  return $this;
}

sub verify ($this, $address) {
  $this->{last_message} = 'Dummy callout will always answer yes';
  return 1;
}

sub is_useable ($this) {
  return $this->{useable};
}

sub last_message ($this) {
  return $this->{last_message};
}

1;
