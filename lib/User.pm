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

package User;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use DB();
use Exporter();
use ReadConfig();
use SystemPref();
use Domain();
use PrefClient();

sub new ($class, $username, $domain) {
  my %prefs;
  my %addresses;

  my $this = {
    id => 0,
    username => '',
    domain => '',
    prefs => \%prefs,
    addresses => \%addresses,
    d => undef,
    db => undef
  };
  bless $this, "User";

  if (defined($username) && defined($domain)) {
    $this->load_from_username($username, $domain);
  } elsif (defined($username) && $username =~ m/^\d+$/) {
    $this->load_from_id($username);
  } elsif (defined($username) && $username =~ m/^\S+\@\S+$/) {
    $this->load_from_linked_address($username);
  }
  return $this, $class;
}

sub load_from_id ($this, $id) {
  return if (!$id);

  my $query = "SELECT u.username, u.domain, u.id FROM user u, WHERE u.id=".$id;
  $this->load($query);
  return;
}

sub load_from_username ($this, $username, $domain) {
  my $query = "SELECT u.username, u.domain, u.id FROM user u, WHERE u.username='".$username."' AND u.domain='".$domain."'";
  $this->load($query);
  return;
}

sub load_from_linked_address ($this, $email) {
  if ($email =~ m/^(\S+)\@(\S+)$/) {
    $this->{domain} = $2;
  }

  $this->{addresses}->{$email} = 1;

  my $query = "SELECT u.username, u.domain, u.id FROM user u, email e WHERE e.address='".$email."' AND e.user=u.id";
  $this->load($query);
  return;
}

sub load ($this, $query) {
  if (!$this->{db}) {
    $this->{db} = DB->db_connect('slave', 'st_config', 0);
  }
  my %userdata = $this->{db}->getHashRow($query);
  if (keys %userdata) {
    $this->{username} = $userdata{'username'};
    $this->{domain} = $userdata{'domain'};
    $this->{id} = $userdata{'id'};
  }
  return 0;
}

sub get_addresses ($this) {
  if ($this->{id}) {
    ## get registered addresses
    if (!$this->{db}) {
      $this->{db} = DB->db_connect('slave', 'st_config', 0);
    }

    my $query = "SELECT e.address, e.is_main FROM email e WHERE e.user=".$this->{'id'};
    my @addresslist = $this->{db}->getListOfHash($query);
    foreach my $regadd (@addresslist) {
      $this->{addresses}->{$regadd->{'address'}} = 1;
      if ($regadd->{is_main}) {
        foreach my $add (keys %{$this->{addresses}}) {
          $this->{addresses}->{$add} = 1;
        }
        $this->{addresses}->{$regadd->{'address'}} = 2;
      }
    }
  }

  ## adding connector addresses
  $this->{d} = Domain->new($this->{domain}) if (!$this->{d} && $this->{domain});
  if ($this->{d}) {
    if ($this->{d}->get_pref('address_fetcher') eq 'ldap') {
      require SMTPAuthenticator::LDAP;
      my $serverstr =  $this->{d}->get_pref('auth_server');
      my $server = $serverstr;
      my $port = 0;
      if ($serverstr =~ /^(\S+):(\d+)$/) {
        $server = $1;
        $port = $2;
      }
      my $auth = SMTPAuthenticator::LDAP->new($server, $port, $this->{d}->get_pref('auth_param'));
      my @ldap_addesses;
      if ($this->{username} ne '') {
        @ldap_addesses = $auth->fetch_linked_addresses_from_username($this->{username});
      } elsif (scalar(keys %{$this->{addresses}})) {
        my @keys = keys %{$this->{addresses}};
        @ldap_addesses = $auth->fetch_linked_addresses_from_email(pop(@keys));
      }
      if (!@ldap_addesses ) {
        ## check for errors
        if ($auth->{'error_text'} ne '') {
          #print STDERR "Got ldap error: ".$auth->{'error_text'}."\n";
        }
      } else {
        foreach my $add (@ldap_addesses) {
          $this->{addresses}->{$add} = 1;
        }
      }
    }
  }

  return keys %{$this->{addresses}};
}

sub get_main_address ($this) {
  $this->get_addresses() if (!keys %{$this->{addresses}});
  my $first;
  foreach my $add (keys %{$this->{addresses}}) {
    return $add if ($this->{addresses}->{$add} == 2);
    $first = $add if (!$first);
  }
  $this->{d} = Domain->new($this->{domain}) if (!$this->{d} && $this->{domain});
  if ($this->{d}->get_pref('address_fetcher') eq 'at_login') {
    return $this->{username} if ($this->{username} =~ /\@/);
    return $this->{username}.'@'.$this->{domain} if ($this->{username} && $this->{domain});
  }
  return $first if ($first);
  return;
}

sub get_pef ($this, $pref) {
  $this->load_prefs() if (keys %{$this->{prefs}} < 1);

  if (defined($this->{prefs}->{$pref}) && $this->{prefs}->{$pref} ne 'NOTSET') {
    return $this->{prefs}->{$pref};
  }
  ## find out if domain has pref
  if (!$this->{d} && $this->{domain}) {
    $this->{d} = Domain->new($this->{domain});
    return $this->{d}->get_pref($pref) if ($this->{d});
  }
  return $this->{d}->get_pref($pref) if ($this->{d});
  return;
}

sub load_prefs ($this) {
  return 0 unless ($this->{id});
  unless ($this->{db}) {
    $this->{db} = DB->db_connect('slave', 'st_config', 0);
  }

  if ($this->{db} && $this->{db}->ping()) {
    my $query = "SELECT p.* FROM user u, user_pref p WHERE u.pref=p.id AND u.id=".$this->{id};
    my %res = $this->{db}->getHashRow($query);
    return 0 if ( !%res || !$res{id} );
    $this->{prefs}->{$_} = $res{$_} foreach (keys(%{$res}));
  }
  return;
}

