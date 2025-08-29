#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use ReadConfig();
use ElementMapper();

my $info = 1;
my $warning = 1;
my $error = 1;

my $conf = ReadConfig::get_instance();

my $importfile = shift;
if (! -f $importfile ) {
  error("Import file not found !");
  exit 1;
}
my $what = shift;
if (!defined($what)) {
  error("No element type given");
  exit 1;
}
my $flags = shift;
my $nottodeletefile = shift;
my $dontdelete = 1;
if (defined($nottodeletefile)) {
  $dontdelete = 0;
}

### ElementMapper factory called here
my $mapper = ElementMapper::get_element_mapper($what);
if (!defined($mapper)) {
  error("Element type \"$what\" not supported");
  exit 1;
}

my $IMPORTFILE;
unless (open($IMPORTFILE, '<', $importfile)) {
  warning("Could not open import file: $importfile");
  exit 0;
}

my %elements = ();
while (<$IMPORTFILE>) {
  if (/^__DEFAULTS__ (.*)/) {
    # set new defaults
    $mapper->set_new_default($1);
    next;
  }
  my $el_name = $_;
  my $el_params = '';
  if (/(.*)\s*:\s*(.*)/) {
    $el_name = $1;
    $el_params = $2;
  }
  $el_name =~ s/\s//g;
  info("will process element $el_name");
  $mapper->process_element($el_name, $flags, $el_params);
  $elements{$el_name} = 1;
}
close $IMPORTFILE;

my $domainsnottodelete = $nottodeletefile;
my %nodelete = ();
my $NODELETEFILE;
if (open($NODELETEFILE, '<', $domainsnottodelete)) {
  while (<$NODELETEFILE>) {
   my $el = $_;
   chomp($el);
   $nodelete{$el} = 1;
   print "preventing delete for: $el\n";
  }
  close $NODELETEFILE;
}

unless ($dontdelete) {
  my @existing_elements = $mapper->get_existing_elements();
  foreach my $el (@existing_elements) {
    next if (defined($nodelete{$el}));
    if (!defined($elements{$el}) || ! $elements{$el}) {
      $mapper->delete_element($el);
    }
  }
}

sub warning ($text) {
  if ($warning) {
    print $text."\n";
  }
  return;
}

sub error ($text) {
  if ($error) {
    print $text."\n";
  }
  return;
}

sub info ($text) {
  if ($info) {
    print $text."\n";
  }
  return;
}
