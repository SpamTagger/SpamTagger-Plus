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

use Test2::V0;
use Env qw(TABLE_TERM_SIZE);
use IPC::Open3 qw( open3 );;
use File::Spec;
use Cwd qw( abs_path );
use Symbol 'gensym';

my $start = shift || '/usr/spamtagger';
$TABLE_TERM_SIZE = 100;

die "Path '$start' does not exist\n" unless (-d $start);
$start = abs_path($start) unless ($start =~ m/^\//);

open STDERR, '>&STDOUT';
sub check_dir ($path) {
  my $dir;
  opendir($dir, $path);
  while (my $new_path = readdir($dir)) {
    next if ($new_path =~ /^\./);
    if (-f "$path/$new_path" && $new_path =~ /\.p(l|m)$/) {
      open(my $NULL, ">", File::Spec->devnull);
      my $pid = open3(my $in, my $out, my $error = gensym, "perl", "-c", "$path/$new_path");
      my @violations;
      push(@violations, $_) while( <$error> );
      waitpid($pid, 0);
      my $ret = $?;
      # I cannot find documentation on what the return codes mean.
      # They are all powers of 2 >=512 on errors and 0 with no errors.
      #$ret = $ret >> 9;
      is($ret, 0, "$path/$new_path");
      next unless ($ret);
      foreach (@violations) {
        print "$ret $path/$new_path: $_" unless ($_ =~ /(Insecure|had compilation errors)/);
      }
    }
    check_dir($path."/".$new_path) if (-d $path.'/'.$new_path);
  }
  close($dir);
  return;
}

check_dir($start);

done_testing();
