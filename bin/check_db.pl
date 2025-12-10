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
#   This script will compare the actual replica or source database with
#   the up-to-date database from SpamTagger Update Services
#
#   Usage:
#           check_db.pl [-s|-r] [--dbs=database] [--update|--mycheck|--myrepair] [-r|-R]

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib/';
use ReadConfig();
use DB();

my $VERBOSE = 0;
## default behaviour
my $dbtype = 'source';
my $databases = 'st_config,st_spool,st_stats';
my $updatemode = 0;
my $checkmode = 0;
my $repairmode = 0;
my $repcheck = 0;
my $repfix = 0;

## parse arguments
while (my $arg=shift) {
 if ($arg eq "-s") {
   $dbtype='source';
 } elsif ($arg eq '-r') {
   $dbtype='replica';
 } elsif ($arg eq '--update') {
   $updatemode=1;
 } elsif ($arg eq '--mycheck') {
   $checkmode=1;
 } elsif ($arg eq '--myrepair') {
   $repairmode=1;
 } elsif ($arg =~ /\-\-dbs=(\S+)/) {
   $databases=$1;
 } elsif ($arg eq "-r") {
   $repcheck=1;
 } elsif ($arg eq "-R") {
   $repfix=1;
 } else {
   print "unknown argmuent: $arg\n";
   print "Usage: check_db.pl [-s|-r] [--dbs=database] [--update] [--mycheck|--myrepair] [-r|-R]\n";
   exit 1;
 }
}
## check given mode
if (($updatemode + $checkmode + $repairmode) > 1) {
  print "Cannot do more than one thing at once, please choose between --update, --mycheck or --myrepair\n";
  exit 1;
}

my $conf = ReadConfig::get_instance();

## check replication if wanted
if ($repcheck > 0) {
  check_replication_status($repfix);
  exit 0;
}
if ($repfix > 0) {
  if (check_replication_status($repfix)) {
    exit 0;
  }
  sleep 5;
  check_replication_status(0);
  exit 0;
}
## process each database
foreach my $database (split(',', $databases)) {
  output("Processing database: $database");
  if ($database eq "st_stats" && $dbtype eq 'source') {
    output(" avoiding st_stats on a source database");
    next;
  }

  ## connect to database
  my $db = DB->db_connect($dbtype, $database);
  output("Connected to database");

  if ($checkmode) {
    ## mariadb check mode
    my_check_repair_database(\$db, 0);
  } elsif ($repairmode) {
    ## mariadb repair mode
    my_check_repair_database(\$db, 1);
  } elsif ($updatemode) {
    compare_update_database(\$db, $database, 1);
  } else {
    ## output status
    compare_update_database(\$db, $database, 0);
  }

  $db->db_disconnect();
  output("Disconnected from database");
}

if ($updatemode && $dbtype eq 'source') {
  foreach my $dbname ('dmarc_reporting') {
    my $db = DB->db_connect($dbtype, $dbname, 0);
    if ($db && !$db->get_type()) {
       print "Need to create new database $dbname, proceeding...\n";
       add_database($dbtype, $dbname);
    }
    $db->db_disconnect();
  }
}
exit 0;

#######################
## output
sub output ($message) {
  print $message."\n" if ($VERBOSE);
  return;
}

#######################
## get_ref_tables
sub get_ref_tables ($dbname) {
  my %tables;

  my $prefix = 'cf';
  if ($dbname eq 'st_stats') {
    $prefix='st';
  } elsif ($dbname eq 'st_spool') {
    $prefix='sp';
  }

  my $install_dir = $conf->get_option('SRCDIR')."/install/dbs";
  if ($dbname eq 'st_spool') {
    $install_dir .= "/spam";
  }
  my $IDIR;
  opendir($IDIR, $install_dir) or die "could not open table definition directory $install_dir\n";
  while( my $table_file = readdir($IDIR)) {
    next if $table_file =~ /^\./;
    if ($table_file =~ /^t\_$prefix\_(\S+)\.sql/) {
      $tables{$1} = $install_dir."/".$table_file;
    }
  }
  closedir($IDIR);
  return %tables;
}

#######################
## get_actual_tables
sub get_actual_tables ($db_ref) {
  my $db = $$db_ref;
  my %tables_hash;

  my $sql = "SHOW tables;";
  my @tables = $db->get_list($sql);

  foreach my $table (@tables) {
    $tables_hash{$table} = $table;
  }
  return %tables_hash;
}


#######################
## get_ref_fields
sub get_ref_fields ($file) {
  my %fields;
  my $previous = 0;
  my $order = 0;

  my $TABLEFILE;
  open($TABLEFILE, '<', $file) or die("ERROR, cannot open reference database file $file\nABORTED\n");
  my $in_desc = 0;
  while(<$TABLEFILE>) {
    chomp;
    if ( $_ =~ /CREATE\s+TABLE\s+(\S+)\s+\(/ ) {
      $in_desc = 1;
      next;
    }
    if ( $_ =~ /^\s*\)(TYPE\=MyISAM)?\;\s*$/ ) {
      $in_desc = 0;
    }
    if ( $_ =~ /INSERT/) {
      $in_desc = 0;
      next;
    }
    if (! $in_desc) {
      next;
    }
    if ( $_ =~ /^\s*PRIMARY|INDEX|UNIQUE KEY|KEY|^\-\-/ ) {
      next;
    }
    if ( $_ =~ /\s+(\S+)\s+([^\s\(,]+(?:\([^\)]+\))?)(.*)\,?\s*$/ ) {
      my $deffull = $2.$3;
      my $def = $2;
      my $n = $1;
      $def =~ s/\ //g;
      $deffull =~ s/\s*\,\s*$//g;
      $fields{$order."_".$n} = { previous => $previous, def => $def, deffull => $deffull };
      $previous = $n;
      $order = $order + 1;
      next;
    }
  }
  close($TABLEFILE);
  return %fields;
}

#######################
## get_actual_fields
sub get_actual_fields ($db_ref, $tablename) {
  my $db = $$db_ref;
  my %fields;
  my $previous = "";

  my $sql = "DESCRIBE $tablename;";
  my @afields = $db->get_list_of_hash($sql);

  foreach my $f (@afields) {
    my $fname = $f->{Field};
    my $ftype = $f->{Type};
    $fields{$fname} = { previous => $previous, def => $ftype };
    $previous = $1;
  }

  return %fields;
}


#######################
## my_check_repair_database
sub my_check_repair_database ($db_ref, $repair) {
  my $db = $$db_ref;
  my $sql = "";

  my %tables = get_actual_tables(\$db);

  foreach my $tname (keys %tables) {
    if ($repair) {
      print "   repairing table: $tname...";
      $sql = "REPAIR TABLE $tname EXTENDED;";
    } else {
      print "   checking table: $tname...";
      $sql = "CHECK TABLE $tname EXTENDED;";
    }
    my %result = $db->get_hash_row($sql);
    print " ".$result{'Msg_text'}."\n";
  }
  return;
}

#######################
## add permission to database
sub add_database ($dbtype, $dbname) {
  $dbtype = 'source' if ($dbtype ne 'replica');

  my $mariadbd = $conf->get_option('SRCDIR')."/etc/init.d/mariadb_".$dbtype;
  print "Restarting $dbtype database to change permissions...\n";
  `$mariadbd restart nopass 2>&1`;
  sleep(20);
  my $dbr = DB->db_connect($dbtype, 'mariadb');
  print "Creating database $dbname...\n";
  $dbr->execute("CREATE DATABASE $dbname");
  print "Adding new permissions...\n";
  $dbr->execute("INSERT INTO db VALUES('%', '".$dbname."', 'spamtagger', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y')");
  $dbr->db_disconnect();
  print "Restarting $dbtype database with new permissions...\n";
  `$mariadbd restart 2>&1`;
  sleep(20);
  my $descfile = $conf->get_option('SRCDIR')."/install/dbs/".$dbname.".sql";
  if (-f $descfile) {
    print "Creating schema...\n";
    my $mariadb = $conf->get_option('SRCDIR')."/bin/st_mariadb";
    if ($dbtype eq 'replica') {
      $mariadb .= " -r $dbname";
    } else {
      $mariadb .= " -s $dbname";
    }
    `$mariadb < $descfile 2>&1`;
  }

  print "Done.\n";
  return;
}

#######################
## check replication status and try to fix if wanted
sub check_replication_status ($fix) {
  my $haserror = 0;
  my $logfile = $conf->get_option('VARDIR')."/log/mariadb_replica/mariadb.log";
  if (! -f $logfile) {
    print "WARNING: replica mariadb log file not found ! ($logfile)\n";
    return 0;
  }
  my $outlog = `tail -4 $logfile`;
  if ($outlog =~ /replication started/ && $outlog =~ /starting replication in log/) {
    print "Replication status: OK\n";
    return 1;
  }
  if (! $fix) {
    print "Replication status: NOT OK !\n";
    return 0;
  }
  $outlog = `grep '[ERROR]' $logfile`;
  if ( $outlog =~ m/Duplicate column name '(\S+)''.*database: '(\S+)'.*TABLE (\S+)/) {
    print "WARNING: a duplicate column has been detected: $1 on table $3 ($2)\n";
    if ($fix) {
      print " ...trying to fix... ";
      my $query = "ALTER TABLE $3 DROP COLUMN $1;";
      my $dbr = DB->db_connect('replica', $2);
      if ( $dbr->execute($query)) {
       my $cmd = $conf->get_option('SRCDIR')."/etc/init.d/mariadb_replica restart >/dev/null 2>&1";
       my $resexec = `$cmd`;
       print " should be fixed!\n";
      } else {
       print " could not modify database. fix failed\n";
       return 0;
      }
      $dbr->db_disconnect();
    }
  }
  return 0;
}

#######################
## compare_update_database
sub compare_update_database ($db_ref, $dbname, $update) {
  my $db = $$db_ref;
  my %reftables = get_ref_tables($dbname);
  my %actualtables = get_actual_tables(\$db);

  #####
  ## check missing things in actual database (from ref to actual)
  ## check tables presence
  foreach my $table (keys %reftables) {
    output "  processing table $table\n";
    ## if missing table
    if (! defined($actualtables{$table})) {
      print "     MISSING table $table..";
      if ($update) {
        my $type = '-s';
        if ($dbtype eq 'replica') {
          $type = '-r';
        }
        my $cmd = $conf->get_option('SRCDIR')."/bin/st_mariadb $type < ".$reftables{$table} ." 2>&1";
        my $res = `$cmd`;
        if (! $res eq '' ) {
          print "ERROR, cannot create database: $res\nABORTED\n";
          exit 1;
        } else {
          print " FIXED !";
        }
      }
      print "\n";
      next;
    }

    ## compare and repair table
    if (!compare_update_table(\$db, $table, $reftables{$table}, $update)) {
      print "ERROR, cannot update table $table\nABORTED\n";
      exit 1;
    }

  }
  return;
}

#######################
## compare_update_table
sub compare_update_table ($db_ref, $tablename, $tablefile, $update) {
  my $db = $$db_ref;

  my %reffields = get_ref_fields($tablefile);
  my %actualfields = get_actual_fields(\$db, $tablename);
  my %nonofields;

  #####
  ## check missing columns
  foreach my $reff (sort (keys %reffields)) {
    my $f = $reff;
    $f =~ s/^(\d+\_)//;
    $nonofields{$f} = $reffields{$reff};
    if (! defined($actualfields{$f})) {
      print "     MISSING column $tablename.$f (after ".$reffields{$reff}{previous}.")";
      if ($update) {
        my $after = "";
        if (! $reffields{$reff}{previous} eq '') {
          $after = " AFTER ".$reffields{$reff}{previous};
        }
        my $sql = "ALTER TABLE $tablename ADD COLUMN ".$f." ".$reffields{$reff}{deffull}.$after.";";
        if (! $db->execute($sql)) {
          print " ERROR, cannot create column: ".$db->get_error()."\nABORTED\n";
          exit 1;
        } else {
          print " FIXED !\n";
        }
      }
      print "\n";
    } else {
      my $clean = $reff;
      $clean =~ s/^\d+_//;
      if (lc($reffields{$reff}{'def'}) ne lc($actualfields{$clean}{'def'})) {
        print "     INCORRECT column type '".$actualfields{$clean}{'def'}."' != '".$reffields{$reff}{'def'}."' $tablename.$f";
        if ($update) {
          my $sql = "ALTER TABLE $tablename MODIFY $clean $reffields{$reff}{'deffull'};";
          if (! $db->execute($sql)) {
            print " ERROR, cannot alter column $clean in $tablename: ".$db->get_error()."\nABORTED\n";
            exit 1;
          } else {
            print " FIXED !\n";
          }
        }
      }
    }
  }

  #####
  ## check useless columns
  foreach my $f (keys %actualfields) {
    if (! defined($nonofields{$f})) {
      print "     USELESS column $tablename.$f..";
      if ($update) {
        my $sql = "ALTER TABLE $tablename DROP COLUMN ".$f.";";
        if (! $db->execute($sql)) {
          print "ERROR, cannot remove column: ".$db->get_error()."\nABORTED\n";
          exit 1;
        } else {
          print " FIXED !";
        }
      }
      print "\n";
    }
  }
  return 1;
}
