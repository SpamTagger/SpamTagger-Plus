#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
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

package MailScanner::Accounting;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use vars qw($VERSION);

use lib "/usr/spamtagger/lib/";
use Email();
use Domain();
use SystemPref();
use StatsClient();

# Constructor.
sub new ($class = 'MailScanner::Accounting', $preposttype = 'post') {
  $preposttype = 'post' if ($preposttype ne 'pre');
  my $this = {
    last_message => '',
    prepost_type => $preposttype
  };

  $this->{statsclient} = StatsClient->new();

  return bless $this, $class;
}

sub check_checkeable_user ($this, $user) {
  unless  ($this->is_user_checkeable($user)) {
    $this->{last_message} = 'Number of licensed users has been exhausted';
    return 0;
  }
  unless ($this->is_user_checkeable_for_domain($user)) {
    $this->{last_message} = 'Number of licensed users for domain has been exhausted';
    return 0;
  }
  return 1;
}

sub check_checkeable ($this, $msg) {
  my $nb_notcheakable = 0;
  my $nb_recipients = @{$msg->{to}};

  foreach my $rcpt (@{$msg->{to}}) {
    unless ($this->is_user_checkeable($rcpt)) {
      $nb_notcheakable++;
    }
  }
  ## only of all recipients are not checkeable, otherwise still filter message
  if ($nb_notcheakable >= $nb_recipients) {
    $this->{last_message} = 'Number of licensed users has been exhausted';
    return 0;
  }

  ## check per domain
  $nb_notcheakable = 0;
  foreach my $rcpt (@{$msg->{to}}) {
    $nb_notcheakable++ unless ($this->is_user_checkeable_for_domain($rcpt));
  }
  ## only of all recipients are not checkeable, otherwise still filter message
  if ($nb_notcheakable >= $nb_recipients) {
    $this->{last_message} = 'Number of licensed users for domain has been exhausted';
    return 0;
  }

  return 1;
}

sub is_user_checkeable ($this, $user) {
  if ($user =~ m/(\S+)\@(\S+)/) {
    my $domain_name = $2;
    my $local_part = $1;

    if ($this->{statsclient}->get_value('user:'.$domain_name.":".$local_part.":unlicenseduser") > 0) {
      ## if user already has exhausted license
      return 0;
    }
    if ($this->{statsclient}->get_value('user:'.$domain_name.":".$local_part.":licenseduser") > 0) {
      ## user already has been counted
      return 1;
    }

    my $maxusers = 0;
    if ($maxusers > 0) {
      my $current_count = $this->{statsclient}->get_value('global:user');
      $current_count++ if ($this->{prepost_type} eq 'pre');
      if ($current_count > $maxusers) {
        $this->{statsclient}->add_value('user:'.$domain_name.":".$local_part.":unlicenseduser", 1);
        return 0;
      } else {
        $this->{statsclient}->add_value('user:'.$domain_name.":".$local_part.":licenseduser", 1);
      }
    }
  }
  return 1;
}

sub is_user_checkeable_for_domain ($this, $user) {

  if ($user =~ m/(\S+)\@(\S+)/) {
    my $domain_name = $2;
    my $local_part = $1;

    if ($this->{statsclient}->get_value('user:'.$domain_name.":".$local_part.":domainunlicenseduser") > 0) {
      ## if user already has exhausted license
      return 0;
    }
    if ($this->{statsclient}->get_value('user:'.$domain_name.":".$local_part.":domainlicenseduser") > 0) {
      ## user already has been counted
      return 1;
    }

    my $domain = Domain::create($domain_name);
    if ($domain) {
      my $maxusers = $domain->get_pref('acc_max_daily_users');
      if ($maxusers > 0) {
        my $domain_subject = 'domain:'.$domain_name.":user";
        my $current_count = $this->{statsclient}->get_value($domain_subject);
        $current_count++ if ($this->{prepost_type} eq 'pre');
        if ($current_count > $maxusers) {
          $this->{statsclient}->add_value('user:'.$domain_name.":".$local_part.":domainunlicenseduser", 1);
          return 0;
        } else {
          $this->{statsclient}->add_value('user:'.$domain_name.":".$local_part.":domainlicenseduser", 1);
        }
      }
    }
  }
  return 1;
}

sub get_last_message ($this) {
  return $this->{last_message};
}

1;

