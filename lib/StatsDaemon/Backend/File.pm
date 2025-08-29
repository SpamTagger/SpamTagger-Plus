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
#

package StatsDaemon::Backend::File;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use threads();
use threads::shared();
use ReadConfig();
use File::Path qw(mkpath);
use Fcntl qw(:flock SEEK_END);

my $_need_day_change : shared = 0;
my $_changing_day : shared = 0;

sub new ($class, $daemon) {
  my $conf = ReadConfig::get_instance();

  my $this = {
    'class' => $class,
    'daemon' => $daemon,
    'data' => undef,
    'basepath' => $conf->get_option('VARDIR') . '/spool/spamtagger/stats',
    'today_filename' => '_today',
    'history_filename' => '_history'
  };

  bless $this, $class;

  foreach my $option (keys %{ $this->{daemon} }) {
  	if (defined($this->{$option})) {
  		$this->{$option} = $this->{daemon}->{$option};
  	}
  }
  if (! -d $this->{basepath}) {
  	mkpath($this->{basepath});
  	$this->do_log("base path created: ".$this->{basepath});
  }
  $this->do_log("backend loaded", 'statsdaemon');

  $this->{data} = $StatsDaemon::data_;
  return $this;
}

sub thread_init ($this) {
  $this->do_log("backend thread initialization", 'statsdaemon');
  return;
}

sub access_flat_element ($this, $element) {
  my $value = 0;

  my ($path, $file, $base, $el_key) = $this->get_path_file_base_and_key_from_element($element);
  my $FILE;
  if ( open($FILE, '<', $file)) {
  	while (<$FILE>) {
  		if (/^([^:\s]+)\s*:\s*(\d+)/) {
  			my $newkey = $1;
  			my $v = $2;
  			if ($newkey eq $el_key) {
  				$value = $v;
  			} else {
  				$this->{daemon}->create_element($base.":".$newkey);
          $this->{daemon}->set_element_value_by_name($base.":".$newkey, 'value', $v);
  			}
  		}
  	}
    close $FILE;
  }

  return $value;
}

sub stabilize_flat_element ($this, $element) {
  my ($path, $file, $base, $el_key) = $this->get_path_file_base_and_key_from_element($element);
  if (! -d $path) {
    mkpath($path);
  }

  my $FILE;
  if ($this->{daemon}->is_changing_day()) {
  	my $sfile = $path."/".$this->{history_filename};
  	unless (open($FILE, ">>", $sfile)) {
  		return '_CANNOTWRITEHISTORYFILE';
  	}
  	my $cdate = $this->{daemon}->get_current_date();
  	print $FILE sprintf('%.4u%.2u%.2u' ,$cdate->{'year'},$cdate->{'month'},$cdate->{'day'}).":";
  	print $FILE $el_key.":".$this->{daemon}->get_element_value_by_name($element, 'value')."\n";
  	close $FILE;

  	unlink($file) if (-f $file);
  	return 'STABILIZED';
  }

  my %els = ();
  if ( open($FILE, '<', $file)) {
    while (<$FILE>) {
      if (/^([^:\s]+)\s*:\s*(\d+)/) {
      	my $key = $1;
      	my $val = $2;
      	if ($key ne $el_key) {
        	$els{$1} = $2;
      	}
      }
    }
    close $FILE;
  }

  if ( open($FILE, ">", $file)) {
  	flock $FILE, LOCK_EX;
    foreach my $key (keys %els) {
    	print $FILE $key.":".$els{$key}."\n";
    }
    print $FILE $el_key.":".$this->{daemon}->get_element_value_by_name($element, 'value')."\n";
    flock $FILE, LOCK_UN;
    close $FILE;
  }

  return 'STABILIZED';
}

sub get_stats ($this, $start, $stop, $what, $data) {
  # TODO: this doesn't do anything...
  return 'OK';
}

sub announce_month_change ($this) {
  return;
}

sub do_log ($this, $message, $given_set, $priority) {
  my $msg = $this->{class}." ".$message;
  if ($this->{daemon}) {
    $this->{daemon}->do_log($msg, $given_set, $priority);
  }
  return;
}

sub get_path_file_base_and_key_from_element ($this, $element) {
	my @els = split(/:/, $element);
  my $key = pop @els;

  my $path = $this->{basepath}.'/'.join('/',@els);
  my $file = $path.'/'.$this->{today_filename};
  my $base = join(':', @els);
  return (lc($path), lc($file), lc($base), lc($key));
}

1;
