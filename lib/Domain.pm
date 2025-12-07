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

package Domain;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use DB();
use ReadConfig();
use PrefClient();
use SystemPref();
use ConfigTemplate();

sub new ($class, $name) {
  my $this = {
    name => $name,
    prefs => {},
  };

  bless $this, $class;
  return $this;
}

sub get_pref ($this, $pref, $default) {
  unless (defined($this->{prefs}) && defined($this->{prefs}{$pref})) {

    my $prefclient = PrefClient->new();
    $prefclient->setTimeout(2);
    my $dpref = $prefclient->getPref($this->{name}, $pref);
    if (defined($dpref) && $dpref !~ /^_/) {
      if ($pref eq 'support_email' && $dpref eq 'NOTFOUND') {
        $dpref = '';
      }
      $this->{prefs}->{$pref} = $dpref;
      return $dpref;
    }
    $this->loadPrefs();
  }

  return $this->{prefs}->{$pref} if (defined($this->{prefs}->{$pref}));
  return $default if (defined($default));
  return "";
}

sub load_prefs ($this) {
  my $conf = ReadConfig::get_instance();
  my $preffile = $conf->get_option('VARDIR')."/spool/spamtagger/prefs/".$this->{name}."/prefs.list";

  my @dlist = ($this->{name}, '*', '_joker', '_global');

  ## try to load from db
  my $db = DB->db_connect('replica', 'st_config', 0);

  my %res;
  if ($db && $db->ping()) {
    for my $d ( @dlist ) {
      my $query = "SELECT p.* FROM domain d, domain_pref p WHERE d.prefs=p.id AND d.name='".$d."'";
      %res = $db->get_hash_row($query);
      if ( %res && $res{id} ) {
        $this->{prefs}->{$_} = $res{$_} foreach (keys(%res));
        return 1;
      }
    }
  }

  ## finaly try to find a valid preferences file
  my $found = 0;
  for my $d ( @dlist ) {
    $preffile = $conf->get_option('VARDIR')."/spool/spamtagger/prefs/".$d."/prefs.list";
    if ( -f $preffile) {
      $found = 1;
      last;
    }
  }
  return 0 unless ($found);
  return 0 unless (open(my $PREFFILE, '<', $preffile));
  while (<$PREFFILE>) {
    $this->{prefs}->{$1} = $2 if (/^(\S+)\s+(.*)$/);
  }
  close $PREFFILE;
  return;
}

sub dump_prefs ($this, $replica_db) {
  $replica_db = DB->db_connect('replica', 'st_config') unless ($replica_db);
  my $query =
    "SELECT d.id, p.viruswall, p.spamwall, p.virus_subject, p.content_subject, p.spam_tag,
    p.language, p.report_template, p.support_email, p.delivery_type,
    p.enable_whitelists, p.enable_warnlists, p.enable_blacklists, p.notice_wwlists_hit, p.warnhit_template
    FROM domain d, domain_pref p WHERE d.prefs=p.id AND d.name='".$this->{name}."'";

  my %res = $replica_db->getHashRow($query);

  $this->dumpPrefsFromRow(\%res);
  return;
}

sub dump_prefs_from_row ($this, $row) {
  my %res = %{$row};
  print "CANNOTFINDPREFS" unless (%res && defined($res{id}));
  my $conf = ReadConfig::get_instance();
  my $prefdir = $conf->get_option('VARDIR')."/spool/spamtagger/prefs/".$this->{name};
  my $preffile = $prefdir."/prefs.list";

  my $stuid = getpwnam('SpamTagger');

  my @prefs_to_dump = (
    'viruswall', 'report_template', 'virus_subject', 'enable_whitelists', 'language',
    'warnhit_template', 'support_email', 'spamwall', 'enable_warnlists', 'content_subject',
    'notice_wwlists_hit', 'spam_tag', 'delivery_type'
  );

  unless ( -d $prefdir ) {
    unless ( mkdir($prefdir)) {
      print "CANNOTMAKEPREFDIR ($prefdir)";
      return 0;
    }
    my $uid = getpwnam( 'SpamTagger' );
    my $gid = getgrnam( 'SpamTagger' );
    chown $uid, $gid, $prefdir;
  }

  my $PREFFILE;
  unless (open($PREFFILE, ">", $preffile)) {
    print "CANNOTWRITEPREFFILE";
    return 0;
  }

  foreach my $k (keys %res) {
    if (grep { $k  } @prefs_to_dump) {
      $res{$k} = "" unless ( defined($res{$k}));
      print $PREFFILE "$k ".$res{$k}."\n";
    }
  }
  close $PREFFILE;
  chown $stuid, $stuid, $preffile;

  ## dump ldap callout file
  if ($this->getPref('adcheck') eq 'true') {

    my $syspref = SystemPref::get_instance();
    my $ldapserver = $syspref->getPref('ad_server');
    my ($ad_basedn, $ad_binddn, $ad_pass) = split(':', $syspref->getPref('ad_param'));

    if ($this->getPref('ldapcallout') ne 'NOTFOUND' && $this->getPref('ldapcallout') != 0) {
     print "specific ldap config\n";
    }

    my $template = ConfigTemplate->new(
      "etc/exim/ldapcallout_template",
      $conf->get_option('VARDIR')."/spool/spamtagger/callout/"
        . $this->getPref('name').".ldapcallout");

    my %rep;
    $rep{'__AD_BINDDN__'} = $ad_binddn;
    $rep{'__AD_PASS__'} = $ad_pass;
    $rep{'__AD_SERVERS__'} = $ldapserver;
    $rep{'__AD_BASEDN__'} = $ad_basedn;

    my $specserver = $this->getPref('ldapcalloutserver');
    my $specparams = $this->getPref('ldapcalloutparam');
    $rep{'__AD_SERVERS__'} = $specserver if ($specserver ne '');
    if ($specserver ne '' && $specparams =~ m/^([^:]+):([^:]*):([^:]*)$/) {
      $rep{'__AD_BINDDN__'} = $2;
      $rep{'__AD_PASS__'} = $3;
      $rep{'__AD_SERVERS__'} = $specserver;
      $rep{'__AD_BASEDN__'} = $1;
    }
    $template->setReplacements(\%rep);
    my $ret = $template->dumpFile();
  }
  return;
}

sub dump_local_addresses ($this, $replica_db) {
  my $stuid = getpwnam('SpamTagger');
  my $conf = ReadConfig::get_instance();

  $replica_db = DB->db_connect('replica', 'st_config') unless ($replica_db);

  my $query = "SELECT e.address FROM email e WHERE e.address LIKE '%@".$this->{name}."'";

  my $file = $conf->get_option('VARDIR')."/spool/spamtagger/addresses/".$this->{name}.".addresslist";
  my $OUTFILE;
  unless (open($OUTFILE, ">", $file)) {
    unlink($file) if (-e $file); ## in case we cannot write to file, try to remove it
    return 0;
  }
  my @res = $replica_db->getListOfHash($query);
  foreach my $addrow (@res) {
    if (defined($addrow->{'address'}) && $addrow->{'address'} =~ m/(\S+)\@/) {
      print $OUTFILE $1."\n";
    }
  }
  close $OUTFILE;
  chown $stuid, $file;
  return;
}

1;
