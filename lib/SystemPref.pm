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

package SystemPref;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use ReadConfig();
use DB();

our $one_true_self;

## singleton stuff
sub get_instance {
  $one_true_self = create() unless ($one_true_self);
  return $one_true_self;
}

sub new ($class = "SystemPref", $name = "SystemPref") {
  my %prefs;

  my $conf = ReadConfig::get_instance();
  my $preffile = $conf->get_option('VARDIR')."/spool/spamtagger/prefs/_global/prefs.list";
  my $prefdir = $conf->get_option('VARDIR')."/spool/spamtagger/prefs/_global/";
  my $this = {
    name => $name,
    prefdir => $prefdir,
    preffile => $preffile,
    prefs => \%prefs
  };

  return bless $this, $class;
}

sub get_pref ($this, $pref, $default) {
  if (!defined($this->{prefs}) || !defined($this->{prefs}->{id})) {
    my $prefclient = PrefClient->new();
    $prefclient->set_timeout(2);
    my $dpref = $prefclient->get_pref('_global', $pref);
    if (defined($dpref) && $dpref !~ /^_/) {
      $this->{prefs}->{$pref} = $dpref;
      return $dpref;
    }
    ## fallback loading
    $this->load_prefs();
  }

  return $this->{prefs}->{$pref} if (defined($this->{prefs}->{$pref}));
  return $default if (defined($default));
  return "";
}

sub load_prefs ($this) {
  my $PREFFILE;
  return 0 unless (-f $this->{preffile});
  return 0 unless (open($PREFFILE, '<', $this->{preffile}));
  while (<$PREFFILE>) {
    $this->{prefs}->{$1} = $2 if (/^(\S+)\s+(.*)$/);
  }
  close $PREFFILE;
  return;
}

sub dump_prefs ($this) {
  my $replica_db = DB->db_connect('replica', 'st_config');
  my %prefs = $replica_db->get_hash_row("SELECT * FROM antispam");
  my %conf = $replica_db->get_hash_row("SELECT use_ssl, servername FROM httpd_config");
  my %sysconf = $replica_db->get_hash_row("SELECT summary_from, analyse_to FROM system_conf");

  if (! -d $this->{prefdir} && ! mkdir($this->{prefdir})) {
    print "CANNOTCREATESYSTEMPREFDIR\n";
    return 0;
  }
  my $uid = getpwnam( 'spamtagger' );
  my $gid = getgrnam( 'spamtagger' );
  chown $uid, $gid, $this->{prefdir};

  my $PREFFILE;
  unless (open($PREFFILE, ">", $this->{preffile})) {
    print "CANNOTWRITESYSTEMPREF\n";
    return 0;
  }
  foreach my $p (keys %prefs) {
    $prefs{$p} = '' unless (defined($prefs{$p}));
    print $PREFFILE "$p ".$prefs{$p}."\n";
  }
  foreach my $p (keys %conf) {
    print $PREFFILE "$p ".$conf{$p}."\n";
  }
  foreach my $p (keys %sysconf) {
    print $PREFFILE "$p ".$sysconf{$p}."\n";
  }
  close $PREFFILE;
  chown $uid, $gid, $this->{preffile};
  return 1;
}

1;
