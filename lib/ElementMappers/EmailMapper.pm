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

package ElementMappers::EmailMapper;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

sub create {
  my $this = {
     %prefs => (),
     %field_email => (),
  };

  bless $this, "ElementMappers::EmailMapper";
  $this->{prefs}{'address'} = '';
  $this->{field_email} = {'address' => 1, 'user' => 1, 'is_main' => 1};

  return $this;
}

sub set_new_default ($this, $defstr) {
  foreach my $data (split('\s', $defstr)) {
    if ($data =~ m/(\S+):(\S+)/) {
      $this->{prefs}{$1} = $2;
    }
  }
  return;
}

sub check_element_existence ($this, $address) {
  my $check_query = "SELECT address, pref FROM email WHERE address='$address'";
  my %check_res = $this->{db}->get_hash_row($check_query);
  return $check_res{'prefs'} if (defined($check_res{'prefs'}));
  return 0;
}

sub process_element ($this, $address, $flags, $params) {
  my $update = 1;
  $update = 0 if ($flags =~ m/noupdate/ );
  $this->{prefs}{'address'} = lc($address);

  my $pref = 0;
  $pref = $this->check_element_existence($this->{prefs}{'address'});
  if ($pref > 0 && $update) {
    return 1 unless ($update);
    return $this->update_element($this->{prefs}{'address'}, $pref);
  }
  return $this->add_new_element($this->{prefs}{'address'});
}

sub update_element ($this, $address, $pref) {
  my $set_prefquery = $this->get_pref_query();
  if (! $set_prefquery eq '') {
    my $prefquery = "UPDATE user_pref SET ".$set_prefquery." WHERE id=".$pref;
    $this->{db}->execute($prefquery);
    print $prefquery."\n";
  }

  my $set_emailquery = $this->get_email_query();
  unless ( $set_emailquery eq '') {
    my $email_query = "UPDATE email SET ".$set_emailquery." WHERE address='$address'";
    $this->{db}->execute($email_query);
    print $email_query."\n";
  }
  return;
}

sub get_pref_query ($this) {
  my $set_prefquery = '';
  foreach my $datak (keys %{$this->{prefs}}) {
    if (! defined($this->{field_email}{$datak})) {
      $set_prefquery .= "$datak='".$this->{prefs}{$datak}."', ";
    }
  }
  $set_prefquery =~ s/, $//;
  return $set_prefquery;
}

sub get_email_query ($this) {
  my $set_emailquery = '';
  foreach my $datak (keys %{$this->{prefs}}) {
    if (defined($this->{field_email}{$datak})) {
      $set_emailquery .= "$datak='".$this->{prefs}{$datak}."', ";
    }
  }
  $set_emailquery =~ s/, $//;
  return $set_emailquery;
}

sub add_new_element ($this, $address) {
  my $set_prefquery = $this->get_pref_query();
  my $prefquery = "INSERT INTO user_pref SET id=NULL";
  if (! $set_prefquery eq '') {
    $prefquery .= " , ".$set_prefquery;
  }
  print $prefquery."\n";
  $this->{db}->execute($prefquery.";");

  my $getid = "SELECT LAST_INSERT_ID() as id;";
  my %res = $this->{db}->get_hash_row($getid);
  unless (defined($res{'id'})) {
    print "WARNING ! could not get last inserted id!\n";
    return;
  }
  my $prefid = $res{'id'};

  my $set_emailquery = $this->get_email_query();
  my $query  = "INSERT INTO email SET pref=".$prefid;
  $query .= ", ".$set_emailquery unless ($set_emailquery eq '');
  $this->{db}->execute($query);
  print $query."\n";
  return;
}

sub delete_element ($this, $name) {
  # TODO: Does nothing. Need to actually delete element?
  return;
}

sub get_existing_elements ($this) {
  my $query = "SELECT address FROM email";
  my @res = $this->{db}->get_list($query);

  return @res;
}

1;
