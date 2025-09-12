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

use v5.40;
use warnings;
use utf8;

use Perl::Critic qw(critique);
use Test2::V0;
use Env qw(TABLE_TERM_SIZE);

my $start = shift || '/usr/spamtagger';
$TABLE_TERM_SIZE = 100;

our %args = ();
if (-f $start."/perlcritic.conf") {
  $args{-profile} = $start."/perlcritic.conf"
} elsif (-f $start."/etc/perlcritic.conf") {
  $args{-profile} = $start."/etc/perlcritic.conf"
}
my $critic = Perl::Critic->new( %args );

die "Path '$start' does not exist\n" unless (-d $start);

sub check_dir ($path) {
  my $dir;
  opendir($dir, $path);
  while (my $new_path = readdir($dir)) {
    next if ($new_path =~ /^\./);
    if (-f "$path/$new_path" && $new_path =~ /\.p(l|m)$/) {
      my @violations = $critic->critique("$path/$new_path");
      is(@violations, 0, "$path/$new_path");
      print "$path/$new_path: $_" foreach (@violations);
    }
    check_dir($path."/".$new_path) if (-d $path.'/'.$new_path);
  }
  close($dir);
  return;
}

check_dir($start);

done_testing();
