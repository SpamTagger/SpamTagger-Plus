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

# TODO: This appears to be a dead codepath. There appear to be no options in the WebUI which enable
# 'extcallout(_type|_params)?' in the database so 'create' will always exit with an error.
# Check if this can be removed.

package          SMTPCalloutConnector;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use SystemPref();
use Domain();

sub new ($class, $domainname = 'default_domain') {
  if ($domainname eq 'default_domain') {
    my $system = SystemPref->new();
    $domainname = $system->get_pref('default_domain');
  }
  my $domain = Domain->new($domainname);
  return 0 unless ($domain);

  my $useable = 1;
  my $last_message = '';

  my $domain_pref = $domain->get_pref('extcallout');
  if ($domain_pref ne 'true') {
    $useable = 0;
    $last_message = 'not using external callout';
    return;
  }

  my $this = {
    'domain' => $domain,
    'last_message' => $last_message,
    'useable' => $useable,
    'default_on_error' => 1 ## we accept in case of any failure, to avoid false positives
  };

  return bless $this, $class;
}

sub verify ($this, $address) {
  return $this->{default_on_error} unless ($this->{useable});
  if (!defined($address) || $address !~ m/@/) {
    $this->{last_message} = 'the address to check is invalid';
    return $this->{default_on_error};
  }
  my $type = $this->{domain}->get_pref('extcallout_type');
  if (!defined($type) || $type eq '' || $type eq 'NOTFOUND') {
    $this->{last_message} = 'no external callout type defined';
    return $this->{default_on_error};
  }
  my $class = "SMTPCalloutConnector::".ucfirst($type);
  if (! eval { "require $class" }) {
    $this->{last_message} = 'define external callout type does not exists';
    return $this->{default_on_error};
  }

  my @callout_params = ();
  my $params = $this->{domain}->get_pref('extcallout_param');
  # TODO: Because this code path appears to dead, I'm not sure what the content of extcallout_param
  # is supposed to look like. This shows that colons are substituted with '__C__', but then it goes
  # on to push the values as an array. The 'new' method seems to expect a hashref, so this implies
  # that the string looks like: 'key:value:key:value:key:value'.
  # I don't like creating a hash by assigning an even numbered list, so this would be better if it
  # were to flip-flop between caching a key, and writing the key and value. Then check if there is
  # an unmatched key at the end.
  # Since this doesn't appear to be used, I won't bother touching it right now.
  foreach my $p (split /:/, $params) {
    next if ($p eq 'NOTFOUND');
    $p =~ s/__C__/:/;
    push @callout_params, $p;
  }

  my $connector = $class->new(\@callout_params);

  if ($connector->is_useable()) {
    my $res = $connector->verify($address);
    $this->{last_message} = $connector->last_message();
    return $res;
  }
  $this->{last_message} = $connector->last_message();
  return $this->{default_on_error};
}

sub last_message ($this) {
  my $msg = $this->{last_message};
  chomp($msg);
  return $msg;
}

1;
