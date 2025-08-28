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

package ElementMappers::DomainMapper;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

sub new ($class = "ElementMappers::DomainMapper") {

  my @field_domain_o = ('name', 'destination', 'callout', 'altcallout', 'adcheck', 'forward_by_mx', 'greylist');

  my $this = {
    'prefs' => (
      'name' => '',
      'destination' => '',
    ),
    'field_domain' => (
      'name' => 1,
      'destination' => 1,
      'callout' => 1,
      'altcallout' => 1,
      'adcheck' => 1,
      'forward_by_mx' => 1,
      'greylist' => 1
    ),
    'params' => ()
  };

  return bless $this, $class;
}

sub set_new_default ($this, $defstr) {
  foreach my $data (split('\s', $defstr)) {
    if ($data =~ m/(\S+):(\S+)/) {
      my $val = $2;
      my $key = $1;
      $val =~ s/__S__/ /g;
      $val =~ s/__P__/:/g;
      $this->{prefs}{$key} = $val;
   }
  }
  return;
}

sub check_element_existence ($this, $name) {
  my $check_query = "SELECT name, prefs FROM domain WHERE name='$name'";
  my %check_res = $this->{db}->get_hash_row($check_query);
  return $check_res{'prefs'} if (defined($check_res{'prefs'}));
  return 0;
}

sub process_element ($this, $name, $flags = '', $params = '') {
  my $update = 1;
  $update = 0 if ($flags =~ m/noupdate/);
  $this->{params} = ();
  $this->{prefs}{'name'} = $name;
  foreach my $el (split(':', $params) ) {
    chomp($el);
    $el =~ s/^\s+//;
    push @{$this->{params}}, $el;
  }

  my $pref = $this->check_element_existence($name) || 0;
  if ($pref > 0) {
    return 1 unless ($update);
    return $this->update_element($name, $pref);
  }
  return $this->add_new_element($name);
}

sub update_element ($this, $name, $pref) {
  my $set_prefquery = $this->get_pref_query();
  unless ($set_prefquery eq '') {
    my $prefquery = "UPDATE domain_pref SET ".$set_prefquery." WHERE id=".$pref;
    $this->{db}->execute($prefquery);
    print $prefquery."\n";
  }

  my $set_domquery = $this->get_dom_query();
  unless ($set_domquery eq '') {
    my $dom_query = "UPDATE domain SET ".$set_domquery." WHERE name='$name'";
    $this->{db}->execute($dom_query);
    print $dom_query."\n";
  }
  return;
}

sub get_pref_query ($this) {
  my $set_prefquery = '';
  foreach my $datak (keys %{$this->{prefs}}) {
    unless (defined($this->{field_domain}{$datak})) {
      my $val = $this->{prefs}{$datak};
      $val =~ s/PARAM(\d+)/$this->{params}[$1-1]/g;
      $set_prefquery .= "$datak='".$val."', ";
    }
  }
  $set_prefquery =~ s/, $//;
  return $set_prefquery;
}

sub get_dom_query ($this) {
  my $set_domquery = '';
  foreach my $datak (keys %{$this->{prefs}}) {
    if (defined($this->{field_domain}{$datak})) {
      my $val = $this->{prefs}{$datak};
      $val =~ s/PARAM(\d+)/$this->{params}[$1-1]/g;
      $set_domquery .= "$datak='".$val."', ";
    }
  }
  $set_domquery =~ s/, $//;
  return $set_domquery;
}

sub add_new_element ($this, $name) {
  my $set_prefquery = $this->get_pref_query();
  my $prefquery = "INSERT INTO domain_pref SET id=NULL";
  unless ($set_prefquery eq '') {
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

  my $set_domquery = $this->get_dom_query();
  my $query  = "INSERT INTO domain SET prefs=".$prefid;
  unless ($set_domquery eq '') {
    $query .= ", ".$set_domquery;
  }
  $this->{db}->execute($query);
  print $query."\n";
  return;
}

sub delete_element ($this, $name) {
  my $getprefid = "SELECT prefs FROM domain WHERE name='$name'";
  my %res = $this->{db}->get_hash_row($getprefid);
  unless (defined($res{'prefs'})) {
    print "WARNING ! could not get preferences id for: $name!\n";
    return;
  }
  my $prefid = $res{'prefs'};

  my $deletepref = "DELETE FROM domain_pref WHERE id=$prefid";
  $this->{db}->execute($deletepref);
  print $deletepref."\n";
  my $deletedomain = "DELETE FROM domain WHERE name='$name'";
  $this->{db}->execute($deletedomain);
  print $deletedomain."\n";
  return;
}

sub get_existing_elements ($this) {
  my $query = "SELECT name FROM domain";
  return $this->{db}->get_list($query);
}

1;
