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

package PrefClient;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib '/usr/spamtagger/lib';
use ReadConfig();

use parent qw(SockClient);

sub new ($class) {
  my %msgs = ();

  my $spec_this = {
    %msgs => (),
    currentid => 0,
    socketpath => '',
    timeout => 5,
  };

  my $conf = ReadConfig::get_instance();
  $spec_this->{socketpath} = $conf->get_option('VARDIR')."/run/prefdaemon.sock";

  my $this = $class->SUPER::new($spec_this);

  bless $this, $class;
  return $this;
}

sub set_timeout ($this, $timeout) {
  return 0 if ($timeout !~ m/^\d+$/);
  $this->{timeout} = $timeout;
  return 1;
}

## fetch a pref by calling de pref daemon
sub get_pref ($this, $object, $pref) {
  return '_BADOBJECT' if ($object !~ m/^[-_.!\$#=*&\@a-z0-9]+$/i);
  return '_BADPREF' if ($pref !~ m/^[-_a-z0-9]+$/);

  my $query = "PREF $object $pref";

  return $this->query($query);
}

## fetch a pref, just like getPref but force pref daemon to fetch domain pref if user pref is not found or not set
sub get_recursive_pref ($this, $object, $pref) {
  return '_BADOBJECT' if ($object !~ m/^[-_.!\$#=*&\@a-z0-9]+$/i);
  return '_BADPREF' if ($pref !~ m/^[-_a-z0-9]+$/);

  my $query = "PREF $object $pref R";

  return $this->query($query);
}

sub extract_srs_address ($this, $sender) {
  my $sep = '[=+-]';
  my @segments;
  if ($sender =~ m/^srs0.*/i) {
    @segments = split(/$sep/, $sender);
    my $tag = shift(@segments);
    my $hash = shift(@segments);
    my $time = shift(@segments);
    my $domain = shift(@segments);
    my $remove = "$tag$sep$hash$sep$time$sep$domain$sep";
    $remove =~ s/\//\\\//;
    $sender =~ s/^$remove(.*)\@[^\@]*$/$1/;
    $sender .= '@' . $domain;
  } elsif ($sender =~ m/^srs1.*/i) {
    my @blocks = split(/=$sep/, $sender);
    @segments = split(/$sep/, $blocks[0]);
    my $domain = $segments[scalar(@segments)-1];
    @segments = split(/$sep/, $blocks[scalar(@blocks)-1]);
    my $hash = shift(@segments);
    my $time = shift(@segments);
    my $relay = shift(@segments);
    my $remove = "$hash$sep$time$sep$relay$sep";
    $remove =~ s/\//\\\//;
    $sender = $blocks[scalar(@blocks)-1];
    $sender =~ s/^$remove(.*)\@[^\@]*$/$1/;
    $sender .= '@' . $domain;
  }
  return $sender;
}

sub extract_verp ($this, $sender) {
  if ($sender =~ /^[^\+]+\+.+=[a-z0-9\-\.]+\.[a-z]+/i) {
    $sender =~ s/([^\+]+)\+.+=[a-z0-9\-]{2,}\.[a-z]{2,}\@([a-z0-9\-]{2,}\.[a-z]{2,})/$1\@$2/i;
  }
  return $sender;
}

sub extract_sub_address ($this, $sender) {
  if ($sender =~ /^[^\+]+\+.+=[a-z0-9\-\.]+\.[a-z]+/i) {
    $sender =~ s/([^\+]+)\+.+\@([a-z0-9\-]{2,}\.[a-z]{2,})/$1\@$2/i;
  }
  return $sender;
}

sub extract_sender ($this, $sender) {
  my $orig = $sender;
  $sender = $this->extractSRSAddress($sender);
  $sender = $this->extractVERP($sender);
  $sender = $this->extractSubAddress($sender);
  return 0 if ($orig eq $sender);
  return $sender;
}

sub is_whitelisted ($this, $object, $sender) {
  return '_BADOBJECT' if ($object !~ m/^[-_.!\$+#=*&\@a-z0-9]+$/i);

  my $query = "WHITE $object $sender";
  if (my $result = $this->query("WHITE $object $sender")) {
    return $result;
  }
  $sender = $this->extractSender($sender);
  return if ($sender && result = $this->query("WHITE $object $sender"));
  return 0;
}

sub is_warnlisted ($this, $object, $sender) {
  return '_BADOBJECT' if ($object !~ m/^[-_.!\$+#=*&\@a-z0-9]+$/i);

  if (my $result = $this->query("WARN $object $sender")) {
    return $result;
  }
  $sender = $this->extractSender($sender);
  return if ($sender && $result = $this->query("WARN $object $sender"));
  return 0;
}

sub is_blacklisted ($this, $object, $sender) {
  return '_BADOBJECT' if ($object !~ m/^[-_.!\$+#=*&\@a-z0-9]+$/i);

  my $query = "BLACK $object $sender";
  my $result;
  if ($result = $this->query("BLACK $object $sender")) {
    return $result;
  }
  $sender = $this->extractSender($sender);
  if ($sender && $result = $this->query("BLACK $object $sender")) {
    return $result;
  }
  return 0;
}

sub log_stats {
   my $this = shift;

   my $query = 'STATS';
   return $this->query($query);
}

1;
