#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use File::Basename;
use POSIX;

my $script_name                     = basename($0);
$script_name                        =~ s/\.[^.]*$//;
my $mode                            = $ARGV[0] || '';

our $WATCHDOG_BIN           => '/usr/spamtagger/bin/watchdog/';
our $WATCHDOG_CFG           => '/usr/spamtagger/etc/watchdog/';
# TODO: Verify custom watchdog modules and disabling of build-in via this directory
our $WATCHDOG_CUSTOM        => '/etc/spamtagger/watchdogs/';
our $WATCHDOG_TMP           => '/var/spamtagger/spool/watchdog/';
our $WATCHDOG_PID_FOLDER    => '/var/spamtagger/run/watchdog/';

my $time = time();
my $WATCHDOG_OUTFILE            = $WATCHDOG_TMP . $script_name. '___' .$mode. '_' .$time. '.out';

# Errors
# 1  => could not access $WATCHDOG_BIN directory
# 2  => could not launch sub-process
# 3  => could not fork

# Define the defalut values for any watchdog process where they might be missing
sub defaults ($current_process) {
  $current_process->{TIMEOUT}         = 0;
  $current_process->{EXEC_MODE}       = 'Parralel';
  $current_process->{TAGS}            = 'All';
  $current_process->{ERROR_LEVEL}     = 0;
  $current_process->{DELAY}           = 0;
  $current_process->{NICE}            = 10;
  return;
}

###
# Read in the complete contents of a file
sub slurp_file ($file) {
    my @contains = ();

    my $FILE;
    return (0, @contains) unless (open($FILE, '<', $file) );

    @contains = <$FILE>;
    close($FILE);
    chomp(@contains);

    return(1, @contains)
}

###
# Load the custom parameters for this watchdog
sub load_params ($conf_file, $current_process) {
  my @return;
  my $cle;
  my $values;

  # Load default values
  defaults($current_process);

  # Read in configuration file
  my ($exists, @contains) = slurp_file($conf_file);
  if ( $exists == 0 ) {
    $current_process->{NOFILECONF} = 1;
    return;
  }

  # Load keys and values from file
  foreach (@contains) {
    chomp();
    next if ( /^\s*#/ ) ;
    next if ( /^\s*$/ ) ;

    ($k, $v) = split('=', $_);
    chomp($k);
    chomp($v);

    # Override default values for approved parameters only
    if ($cle =~ /^(TIMEOUT|EXEC_MODE|TAGS|ERROR_LEVEL|DELAY|NICE)$/) {
      $current_process->{$k} = $v;
    } else {
      die($current_process->{'file_no_extension'}." contains invalid parameter $k\n");
    }
  }
  return;
}

# Log results to $MYOUTFILE
sub st_log ($data) {
  my $MYOUTFILE;
  open($MYOUTFILE, '>>', $WATCHDOG_OUTFILE);
  print $MYOUTFILE $data ."\n";
  close $MYOUTFILE;
  return;
}

# MAIN
my @processes        = ();
my @processes_seq    = ();
my @processes_par    = ();
my @launched_process = ();

# Create working directory if it does not already exist.
my @old = ();
if( ! -d $WATCHDOG_TMP  ) {
  mkdir($WATCHDOG_TMP, o755);
# If it does exist, track all existing files
} else {
  @old = glob($WATCHDOG_TMP."*");
}

# Change to watchdog directory
chdir($WATCHDOG_BIN) or exit(1);
# Collect all standard SpamTagger (ST), and custom watchdog modules
my @files = glob('mod_*');
if (-d "$WATCHDOG_CUSTOM/bin/") {
  push(@files,glob($WATCHDOG_CUSTOM.'/bin/mod*'));
}
# Sort alphabetically
@files = sort { $a cmp $b } @files;

foreach my $file (@files) {
  my %current_process  = ();
  # Remove the file extension from the module file
  $current_process{file}              = $file;
  $current_process{file_no_extension} = $file;
  $current_process{file_no_extension} =~ s/\.[^\.]*$//;
  $current_process{name}              = basename($current_process{file_no_extension});
  $current_process{configuration_file} =  $WATCHDOG_CFG.$current_process{file_no_extension}.'.conf';
  if ($current_process{$file_no_extension} != $current_process{name}) {
    $current_process{name} = 'CUSTOM_'.$current_process{name};
    $current_process{configuration_file} =  $WATCHDOG_CUSTOM.'/etc/'.$current_process{file_no_extension}.'.conf';
  }
  # Remove any old results for that module
  my @remaining = ();
  foreach (@old) {
    if ($_ =~ m/$current_process{name}/) {
      unlink($_);
    } else {
      push(@remaining,$_);
    }
  }
  @old = @remaining;
  # Skip module if it is disabled with '.disabled' flag
  if (-e "$WATCHDOG_CUSTOM/etc/$current_process{name}.disabled") {
    print STDERR "Ignoring $current_process{file_no_extension} because it is disabled by '" . $WATCHDOG_CUSTOM."/etc/".$current_process{name}.'.disabled' . "\n";
    next;
  }
  $current_process{pid_file}           =  $WATCHDOG_PID_FOLDER.$current_process{name}.'.pid';
  $current_process{TIMEOUT}            //=  5;
  $current_process{EXEC_MODE}          //=  'Sequence';

  # Load params from configuration file
  load_params($current_process{configuration_file}, \%current_process);

  if ($current_process{EXEC_MODE} eq 'Parralel') {
    push(@processes_par, \%current_process);
  } else {
    push(@processes_seq, \%current_process);
  }
}

# Clear remaining old result files
if (scalar(@old)) {
  foreach (@old) {
    if ((-M "$_") > 1) {
      unlink($_);
    } elsif ($_ =~ m/watchdogs___(All|oneday|dix)_(\d+).out/) {
      unlink($_) unless ($2 eq $time);
    }
  }
}

# Run parallel processes first, then sequential
push(@processes, @processes_par, @processes_seq);

# Launch processes
foreach my $current_process (@processes) {
  # Run processes relevant to this mode
  next unless ( ($mode eq 'All') || ($current_process->{TAGS} =~ m/$mode/) );

  my $pid =  'Not_a_pid';
  # Skip modules with existing pid files that were not removed earlier
  if ( -f $current_process->{pid_file}) {
    st_log("MODULE : $current_process->{file}\nRETURN CODE : N/A\nREPORT : Pid file found. Skipped");
    next;
  }

  # Launch if executable
  if ( -x $current_process->{file} ) {

    # Construct subshell command
    my $command = '';
    if ($current_process->{TIMEOUT} != 0) {
      $command = "timeout $current_process->{TIMEOUT} ";
    }
    if ($current_process->{name} =~ '^CUSTOM_') {
      $command .= "nice --$current_process->{NICE} ". $current_process->{file} . ' ' .$mode.  ' >> /dev/null 2>&1';
    } else {
      $command .= "nice --$current_process->{NICE} ". $WATCHDOG_BIN.$current_process->{file} . ' ' .$mode.  ' >> /dev/null 2>&1';
    }

    # Execute parallel items
    if ($current_process->{EXEC_MODE} eq 'Parralel') {
      # fork and capture new child's PID
      $pid = fork();
      # Exit if fork failed
      exit(3) unless defined($pid);
      unless ($pid) {  # child
        # Run in subshell
        exec $commande;
        # Return error if execution failed
        exit(2);
      }

      $current_process->{pid} = $pid;
      # write a PID file for this module's run
      my $OUTFILE;
      open($OUTFILE, '>', $current_process->{pid_file});
      print $OUTFILE $pid;
      close($OUTFILE);

    # Execute sequential items
    } else {
      system(split(/ /, $commande));
      $current_process->{pid} = 'NA';
      $current_process->{return_code}  = $?>>8;
      unlink $current_process->{pid_file};
    }

    # Track all processes which have been run
    push(@launched_process, $current_process);
  }
}

exit(0);
