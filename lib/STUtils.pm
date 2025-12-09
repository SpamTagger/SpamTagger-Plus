#!/usr/bin/env perl

package STUtils;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = qw( create_lockfile open_as remove_lockfile rmrf );
our $VERSION   = 1.0;

use File::Path qw/make_path/;
use Carp qw( confess );

# Returns 0 if $file cannot be opened
# (1, $file content) otherwise
sub _slurp_file ($file) {
  my @contains = ();

  my $FILE;
  return (0, @contains) unless (open($FILE, '<', $file) );
  @contains = <$FILE>;
  close($FILE);
  chomp(@contains);

  return(1, @contains)
}

sub _create_lockfile ($fullpathname, $timeout, $process_name) {
  my $FILE;
  return 0 unless (open($FILE, '>', $fullpathname));
  print $FILE "$$\n";
  print $FILE "$timeout\n$process_name\n"      if ( defined($timeout) && defined($process_name) );
  close $FILE;

  return 1;
}

sub create_lockfile ($filename, $path = '/var/spamtagger/spool/tmp/', $timeout = undef, $process_name = undef) {
  $path = '/var/spamtagger/spool/tmp/'.$path unless ( $path =~ /^\// );
  $path .= '/' unless ($path  =~ /\/$/);

  make_path($path, {mode => 0777}); ## no critic (leading zero for octal notation)

  my $fullpathname = $path . $filename;

  unless ( -e $fullpathname ) {
    my $rc = _create_lockfile($fullpathname, $timeout, $process_name);
    return $rc;
  }

  my ($rc, $pid, $old_timeout, $old_process_name) = _slurp_file($fullpathname);
  return 0 if ($rc == 0);

  return 0 unless ( defined ($old_timeout) );

  if ( time - $old_timeout > 0) {
    kill 'KILL', $pid;
    unlink $fullpathname;

    $rc = create_lock_file($fullpathname, $timeout, $process_name);
    return $rc;
  }
  return 0;
}

sub open_as($file, $method=">", $chmod=0664, $chown='spamtagger:spamtagger') {
    my ($uid, $gid) = split(/:/,$chown);
    $uid = getpwnam( $uid );
    $gid = getgrnam( $gid );
    my ($path,$filename) = $file =~ m#(.*)/([^/]*)$#;
    $path = getcwd().'/'.$path unless ($path =~ m#^/#);

    if ( ! -d $path ) {
        confess ("Failed to create $path\n") unless (make_path($path, {mode => $chmod, user => $uid, group => $gid}));
    }

    confess ("$file does not exist\n") if ($method eq "<" && ! -e "$file");

    if ( ! -e $path.'/'.$filename ) {
        confess("Failed to create $path/$filename\n") unless touch("$path/$filename");
    }

    confess "Failed to set mode for ${path}/${filename} to ".sprintf("%o",$chmod)."\n" unless chmod($chmod, $path.'/'.$filename);
    confess "Failed to give ownership of $path/$filename to $uid:$gid\n" unless chown($uid, $gid, $path.'/'.$filename);

    my $mlong = 'read/write';
    $mlong = 'read' if ($method eq '<');
    $mlong = 'write' if ($method eq '>');
    $mlong = 'append' if ($method eq '>>');
    if (open (my $fh, $method, "${path}/${filename}")) {
        return \$fh;
    } else {
        confess("Failed to open $path/$filename for $mlong: $!\n");
    }
}

sub rmrf($path) {
    if (-d $path) {
        rmrf($_) foreach (glob($path."/*"));
        rmdir($path);
    } else {
        unlink($path);
    }
}

sub remove_lockfile ($filename, $path = '/var/spamtagger/spool/tmp/') {
  $path = '/var/spamtagger/spool/tmp/'.$path unless ( $path =~ /^\// );
  $path .= '/' unless ($path  =~ /\/$/);

  my $fullpathname = $path . $filename;

  my $rc = unlink $fullpathname;

  return $rc;
}


1;
