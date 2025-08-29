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
#   This module will dump a configuration file based on template

package ConfigTemplate;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib '/usr/spamtagger/lib';
use ReadConfig();

my $conf = ReadConfig::get_instance();
my $SRCDIR=$conf->get_option('SRCDIR');
my $VARDIR=$conf->get_option('VARDIR');

###
# create the dumper
# @param  $template    string  base template file
# @param  $targetfile  string  target config file
# @return              this
###
sub new ($class, $templatefile, $targetfile) {
  $templatefile =~ s/__SRCDIR__/$SRCDIR/g;
  $templatefile =~ s/__VARDIR__/$VARDIR/g;
  if ($templatefile =~ m/^[^\/]/) {
    $templatefile = $conf->get_option('SRCDIR')."/".$templatefile;
  }
  $targetfile =~ s/__SRCDIR__/$SRCDIR/g;
  $targetfile =~ s/__VARDIR__/$VARDIR/g;
  if ($targetfile =~ m/^[^\/]/) {
    $targetfile = $conf->get_option('SRCDIR')."/".$targetfile;
  }

  my %replacements = ();
  my %subtemplates = ();
  my %conditions = ();

  my $this = {
    templatefile => $templatefile,
    targetfile => $targetfile,
    %replacements => (),
    %subtemplates => (),
    %conditions => ()
  };

  bless $this, "ConfigTemplate";

  $this->preParseTemplate();
  return $this, $class;
}

###
# preparse template and variables
# @return        boolean   true on success, false on failure
###
sub pre_parse_template ($this) {

  my $in_template = "";
  my $FILE;
  return 0 unless (open($FILE, '<', $this->{templatefile}));
  while (<$FILE>) {
    my $line = $_;

    if ($line =~ /\_\_TMPL\_([A-Z0-9]+)\_START\_\_/) {
      $in_template = $1;
      $this->{subtemplates}{$in_template} = "";
      next;
    }
    if ($line =~ /\_\_TMPL\_([A-Z0-9]+)\_STOP\_\_/) {
      $in_template = "";
      next;
    }
    if ($in_template !~ /^$/) {
      $this->{subtemplates}{$in_template} .= $line;
      next;
    }
  }
  close $FILE;
  return 1;
}

sub get_sub_template ($this, $tmplname) {
  if (defined($this->{subtemplates}{$tmplname})) {
    return $this->{subtemplates}{$tmplname};
  }
  return "";
}

###
# set the tag replacement values
# @param  replace   array_h  handle of array of rplacements with tag as keys
# @return           boolean  true on success, false on failure
###
sub set_replacements ($this, $replace) {
  foreach my $tag (keys %{$replace}) {
    $this->{replacements}{$tag} = $replace->{$tag};
  }
  return 1;
}


###
# dump to destination file
###
sub dump_file ($this) {
  my ($FILE, $TARGET);
  return 0 unless (open($FILE, '<', $this->{templatefile}));
  return 0 unless (open($TARGET, ">", $this->{targetfile}));

  my $ret;
  my $in_hidden = 0;
  my $ev_hidden = 0;
  my @if_hist = ();
  my $if_hidden = 0;
  my $lc = 0;
  while (<$FILE>) {
    my $line = $_;
    $lc++;

    if ($line =~ /__IF__\s+(\S+)/) {
      if ($this->getCondition($1)) {
        push @if_hist, $1;
      } else {
        push @if_hist, "!".$1;
        $if_hidden++;
      }
      next;
    }

    if ($line =~ /__ELSE__\s+(\S+)/) {
      unless (scalar(@if_hist)) {
        die "__ELSE__ $1 without preceeding __IF__ (".$this->{templatefile}.":$lc)\n";
      }
      if ($if_hist[scalar(@if_hist)-1] eq $1) {
        $if_hist[scalar(@if_hist)-1] = '!' . $if_hist[scalar(@if_hist)-1];
        $if_hidden++;
      } elsif ($if_hist[scalar(@if_hist)-1] eq "!".$1) {
        $if_hist[scalar(@if_hist)-1] =~ s/^!//;
        $if_hidden--;
      } else {
        die "__ELSE__ tag $1 without preceeding __IF__ (".$this->{templatefile}.":$lc)\n";
      }
      next;
    }

    if ($line =~/__FI__/) {
      unless (scalar(@if_hist)) {
        die "__FI__ without preceeding __IF__ (".$this->{templatefile}.":$lc)\n";
      }
      if ($if_hist[scalar(@if_hist)-1] =~ /^!/) {
        $if_hidden--;
      }
      pop @if_hist;
      next;
    }

    if ($line =~  /__EVAL__\s+(.*)$/) {
      if (eval { "$1" }) {
        $ev_hidden = 1;
      } else {
        $ev_hidden = 0;
      }
      next;
    }
    if ($line =~/__LAVE__/) {
      $ev_hidden = 0;
      next;
    }
    # Includes a file in the exim configuration
    # First looks for a equivalent customised file
    if ($line =~/__INCLUDE__ *(.*)/) {
      next if ($if_hidden );
      my $inc_file = $1;
      my $path_file;
      $inc_file =~ s/_template$//;
      # Version using .include_if_exists
      if ( -f "$SRCDIR/etc/exim/custom/$inc_file" ) {
        $path_file = "$SRCDIR/etc/exim/custom/$inc_file";
        #$ret .= ".include_if_exists __SRCDIR__/etc/exim/custom/$inc_file\n";
      } elsif ( -f "$SRCDIR/etc/exim/$inc_file" ) {
        $path_file = "$SRCDIR/etc/exim/$inc_file";
        #$ret .= ".include_if_exists __SRCDIR__/etc/exim/$inc_file\n";
      }

      my $PATHFILE;
      open($PATHFILE, '<', $path_file);
      my @contains = <$PATHFILE>;
      close($PATHFILE);
      chomp(@contains);
      $ret .= "$_\n" foreach (@contains);
      next;
    }
    if ($line =~  /\_\_TMPL\_([A-Z0-9]+)\_START\_\_/) {
      $in_hidden = 1;
      next;
    }
    if ($line =~ /\_\_TMPL\_([A-Z0-9]+)\_STOP\_\_/) {
      $in_hidden = 0;
      next;
    }

    if (!$in_hidden && !$if_hidden && !$ev_hidden) {
      $ret .= $line;
    }
  }
  close $FILE;
  ## do the replacements

  ## replace well known tags
  my %wellknown = (
    '__SRCDIR__' => $conf->get_option('SRCDIR'),
    '__VARDIR__' => $conf->get_option('VARDIR'),
  );

  ## replace given tags
  foreach my $tag (keys %{$this->{replacements}}) {
    if (!defined($this->{replacements}{$tag})) {
      $this->{replacements}{$tag} = "";
    }
    if ( defined ($ret) ) {
      $ret =~ s/$tag/$this->{replacements}{$tag}/g;
    }
  }

  foreach my $tag ( keys %wellknown ) {
    if ( defined ($ret) ) {
      $ret =~ s/$tag/$wellknown{$tag}/g;
    }
  }

  if ( defined ($ret) ) {
    print $TARGET $ret;
  }
  close $TARGET;
  my $uid = getpwnam( 'spamtagger' );
  my $gid = getgrnam( 'spamtagger' );
  chown $uid, $gid, $this->{targetfile};
  return 1;
}

sub set_condition ($this, $condition, $value) {
  $this->{conditions}{$condition} = $value;
  return 1;
}

sub get_condition ($this, $condition) {
  if (defined($this->{conditions}{$condition})) {
    return $this->{conditions}{$condition};
  }
  return 0;
}

1;
