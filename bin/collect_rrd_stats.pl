#!/usr/bin/env perl -I../lib/
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004 Olivier Diserens <olivier@diserens.ch>
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
#   This script will dump the domains configuration
#
#   Usage:
#           collect_rrd_stats.pl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use ReadConfig();
use DB();
use RRDStats();
use RRDArchive();

my $mode = shift;
my $m = '';
$m = 'daily' if (defined($mode) && $mode eq 'daily');

my $conf = ReadConfig::get_instance();
exit 0 unless ($conf->get_option('ISSOURCE') =~ /^[Yy]$/);

unless (-d $conf->get_option('VARDIR')."/spool/rrdtools") {
  mkdir $conf->get_option('VARDIR')."/spool/rrdtools";
}

$conf->get_option('SRCDIR');

# get stats to plot
my @stats = ('cpu', 'load', 'network', 'memory', 'disks', 'messages', 'spools');

# get hosts to query
my $replica_db = DB->db_connect('replica', 'st_config');
my @hosts = $replica_db->get_list_of_hash("SELECT id, hostname FROM replica");

## main hosts loops
foreach my $host (@hosts) {
  my $hostname = $host->{'hostname'};
  my $host_stats = RRDStats::new($host->{'hostname'});

  for my $stattype (@stats) {
    if ($m eq 'daily') {
      $host_stats->create_rrd($stattype);
      $host_stats->plot($stattype, 'daily');
    } else {
      $host_stats->create_rrd($stattype);
      $host_stats->collect($stattype);
      $host_stats->plot($stattype, '');
    }
  }
}

## new rrd collecting scheme
my %collections;
my @collections_list = $replica_db->get_list_of_hash("SELECT id, name, type FROM rrd_stats");
my %dynamic_oids;
foreach my $collection (@collections_list) {
  my $c = RRDArchive::new($collection->{'id'}, $collection->{'name'}, $collection->{'type'});
  $c->get_dynamic_oids(\%dynamic_oids) if (keys %dynamic_oids < 1);
  my @elements = $replica_db->get_list_of_hash("SELECT name, type, function, oid, min, max FROM rrd_stats_element WHERE stats_id=".$collection->{'id'}." order by draw_order");
  $c->add_element($_) foreach (@elements);
  $c->collect(\%dynamic_oids);
}

$replica_db->disconnect();
print "SUCCESSFULL\n";
