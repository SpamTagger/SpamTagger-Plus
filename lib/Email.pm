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
#
#   This module will just read the configuration file

package Email;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use Exporter();
use ReadConfig();
use SystemPref();
use Domain();
use PrefClient();
use User();

sub new ($class, $address) {
  return unless ($address =~ /(\S+)\@(\S+)/);
  my $domain = $2;
  my $d = Domain->new($domain);

  my $this = {
    address => $address,
    domain => $domain,
    prefs => {},
    d => $d,
    user => undef
  };

  bless $this, $class;
  return $this;
}

sub get_pref ($this, $pref, $default) {
  if (!defined($this->{prefs}) || !defined($this->{prefs}{$pref})) {

    my $prefclient = PrefClient->new();
    $prefclient->set_timeout(2);
    my $dpref = $prefclient->get_recursive_pref($this->{address}, $pref);
    if ($dpref !~ /^_/ && $dpref !~ /(NOTSET|NOTFOUND)/) {
      $this->{prefs}->{$pref} = $dpref;
      return $dpref;
    }
    $this->load_prefs();
  }

  if (defined($this->{prefs}->{$pref}) && $this->{prefs}->{$pref} !~ /(NOTSET|NOTFOUND)/ ) {
    return $this->{prefs}->{$pref};
  }
  my $dpref = $this->{d}->get_pref($pref, $default);
  return $dpref if (defined($dpref) && $dpref !~ /(NOTSET|NOTFOUND)/);
  return $default if (defined($default));
  return "";
}

sub get_domain_object ($this) {
  return $this->{d};
}

sub get_address ($this) {
  return $this->{address};
}

sub get_user ($this) {
  $this->{user} = User->new($this->{address}) unless ($this->{user});
  return $this->{user};
}

sub get_user_pref ($this, $pref) {
  $this->get_user();
  return $this->{user}->get_pref($pref) if ($this->{user});
  return;
}

sub load_prefs ($this) {
  require DB;
  my $db = DB->db_connect('slave', 'st_config', 0);

  my $to = $this->{address};
  my $to_domain = $this->{domain};
  my %res;

  if ($db && $db->ping()) {
    my $query = "SELECT p.* FROM email e, user_pref p WHERE e.pref=p.id AND e.address='$to'";
    %res = $db->get_hash_row($query);
      if ( !%res || !$res{id} ) {
        return 0;
      }
  } else {
    return 0;
  }
  foreach my $p (keys %res) {
    $this->{prefs}->{$p} = $res{$p};
  }
  return;
}

sub has_in_white_warn_list ($this, $type, $sender) {
  $sender =~ s/\'//g;
  my $sysprefs = SystemPref::get_instance();
  my $filename = 'white.list';
  if ($type eq 'warnlist') {
    return 0 unless ($sysprefs->get_pref('enable_warnlists'));
    return 0 unless ($this->{d}->get_pref('enable_warnlists') || $this->get_pref('has_warnlist'));
    $filename = 'warn.list';
  } elsif ($type eq 'whitelist') {
    return 0 unless ($sysprefs->get_pref('enable_whitelists'));
    return 0 unless ($this->{d}->get_pref('enable_whitelists') || $this->get_pref('has_whitelist'));
  } elsif ($type eq 'blacklist') {
    $filename = 'black.list';
  }

  my $conf = ReadConfig::get_instance();
  my $basedir = $conf->get_option('VARDIR')."/spool/spamtagger/prefs";
  my $wwfile = $basedir."/_global/".$filename;

  my $prefclient = PrefClient->new();
  $prefclient->set_timeout(2);
  my $retvalues = {'GLOBAL' => 1, 'DOMAIN' => 2, 'USER' => 3 };
  if ($type eq 'whitelist') {
    my $result = $prefclient->is_whitelisted($this->{address}, $sender);
    return $retvalues->{$1} if ($result =~ m/^LISTED (USER|DOMAIN|GLOBAL)/ );
    return $this->loaded_is_ww_listed('white', $sender) if ($result =~ /^_/);
    return 0;
  } elsif ($type eq 'warnlist') {
    my $result = $prefclient->is_warnlisted($this->{address}, $sender);
    return $retvalues->{$1} if ($result =~ m/^LISTED (USER|DOMAIN|GLOBAL)/ );
    return $this->loaded_is_ww_listed('warn', $sender) if ($result =~ /^_/);
    return 0;
  } elsif ($type eq 'blacklist') {
    my $result = $prefclient->is_blacklisted($this->{address}, $sender);
    return $retvalues->{$1} if ($result =~ m/^LISTED (USER|DOMAIN|GLOBAL)/ );
    return $this->loaded_is_ww_listed('black', $sender) if ($result =~ /^_/);
  }
  return 0;

}

sub loaded_is_ww_listed ($this, $type, $sender) {
  require DB;
  my $db = DB->db_connect('slave', 'st_config', 0);

  my $to = $this->{address};
  $sender =~ s/[^a-zA-Z0-9.\-_=+@]//g;
  my %res;

  if ($db && $db->ping()) {
    my $query = "SELECT sender FROM wwlists WHERE recipient='".$this->{address}."' AND type='$type' AND status=1";
    my @senders = $db->get_list_of_hash($query);
    foreach my $listedsender (@senders) {
      return 3 if (list_match($listedsender->{'sender'}, $sender));
    }

    $query = "SELECT sender FROM wwlists WHERE recipient='@".$this->{domain}."' AND type='$type' AND status=1";
    @senders = $db->get_list_of_hash($query);
    foreach my $listedsender (@senders) {
      return 2 if (list_match($listedsender->{'sender'}, $sender));
    }

    $query = "SELECT sender FROM wwlists WHERE recipient='' AND type='$type' AND status=1";
    @senders = $db->get_list_of_hash($query);
    foreach my $listedsender (@senders) {
      return 1 if (list_match($listedsender->{'sender'}, $sender));
    }
  }
  return 0;
}

sub list_match ($reg, $sender) {
  # Use only the actual address as pattern
  if ($reg =~ /^.*<(.*\@.*\..*)>$/) {
    $reg = $1;
  }
  $reg =~ s/\./\\\./g; # Escape all dots
  $reg =~ s/\@/\\\@/g; # Escape @
  $reg =~ s/\*/\.\*/g; # Glob on all characters when using *
  $reg =~ s/\+/\\\+/g; # Escape +
  $reg =~ s/\|/\\\|/g; # Escape |
  $reg =~ s/\{/\\\{/g; # Escape {
  $reg =~ s/\}/\\\}/g; # Escape }
  $reg =~ s/\?/\\\?/g; # Escape ?
  $reg =~ s/[^a-zA-Z0-9\+.\\\-_=@\*\$\^!#%&'\/\?`{|}~]//g; # Remove unwanted characters
  $reg = '.*' if ( $reg eq "" );
  return 1 if ($sender =~ /$reg/i);
  return 0;
}

sub in_ww ($this, $type, $sender, $destination) {
  my $prefclient = PrefClient->new();
  $prefclient->set_timeout(2);

  if ($type eq 'whitelist') {
     return 1 if ($prefclient->is_whitelisted($destination, $sender));
     return 0;
  }
  return 1 if ($prefclient->is_warnlisted($destination, $sender));
  return 0;
}

sub send_warnlist_hit ($this, $sender, $reason, $msgid) {
  require MailTemplate;
  my $template = MailTemplate->new('warnhit', 'warnhit', $this->{d}->get_pref('summary_template'), \$this, $this->get_pref('language'), 'html');

  my %level = (1 => 'system', 2 => 'domain', 3 => 'user');
  my %replace = (
    '__SENDER__' => $sender,
    '__REASON__' => $level{$reason},
    '__ADDRESS__' => $this->{address},
    '__LANGUAGE__' => $this->get_pref('language'),
    '__ID__' => $msgid
  );

  my $from = $this->{d}->get_pref('support_email');
  if ($from eq "") {
    my $sys = SystemPref::get_instance();
    $from = $sys->get_pref('summary_from');
  }
  $template->set_replacements(\%replace);
  return $template->send_message();
}

sub send_ww_hit_notice ($this, $whitelisted, $warnlisted, $sender, $msgh) {
  require MailTemplate;
  my $template = MailTemplate->new('warnhit', 'noticehit', $this->{d}->get_pref('summary_template'), \$this, 'en', 'text');

  my $reason = 'whitelist';
  my $level = $whitelisted;
  if (!$whitelisted) {
    $reason = 'warnlist';
    $level = $warnlisted;
  }
  my %levels = (1 => 'system', 2 => 'domain', 3 => 'user');
  my %replace = (
    '__LEVEL__' => $levels{$level},
    '__LIST__' => $reason,
    '__TO__' => $this->{address},
    '__SENDER__' => $sender
  );

  my $admin = $this->{d}->get_pref('support_email');
  if ($admin eq "") {
    my $sys = SystemPref::get_instance();
    $admin = $sys->get_pref('analyse_to');
  }
  $template->set_replacements(\%replace);
  $template->set_destination($admin);
  $template->add_attachement('TEXT', \$$msgh);
  return $template->send_message();
}

sub get_linked_addresses ($this) {
  $this->{user} = User->new($this->{address}) unless ($this->{user});
  return $this->{user}->get_addresses();
}

1;
