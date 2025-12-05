#!/usr/bin/env perl

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib';
use DB();
use Term::ReadKey qw(ReadKey ReadMode);
use ReadConfig();

my $config = ReadConfig::get_instance();
our $SRCDIR = $config->get_option('SRCDIR');
our $HOSTID = $config->get_option('HOSTID');

my $master_dbh = DB->db_connect('master', 'st_config');
if (!$master_dbh) {
  printf ("ERROR: no master database found on this system. This script will only run on a SpamTagger master host.\n");
  exit 1;
}

my $quit=0;
while (! $quit) {
  system("clear");
  my $required = check_host();
  printf "\n################################\n";
  printf "## SpamTagger slaves manager ##\n";
  printf "################################\n\n";
  printf "1) change host settings";
  if ($required > 0) { printf " (required!)"; }
  printf "\n";
  printf "2) view slaves\n";
  printf "3) delete slave\n";
  printf "4) add slave\n";
  printf "5) set this host as slave\n";
  printf "q) quit\n";
  printf "\nEnter your choice: ";

  ReadMode 'cbreak';
  my $key = <STDIN>;
  ReadMode 'normal';
  chomp($key);

  if ($key =~ /q/) {
    $quit=1;
  } elsif ($key =~ /1/) {
    change_host();
  } elsif ($key =~ /2/) {
    view_slaves();
  } elsif ($key =~ /3/) {
    delete_slave();
  } elsif ($key =~ /4/) {
    add_slave();
  } elsif ($key =~ /5/) {
    set_as_slave();
  }
}

$master_dbh->db_disconnect();

printf "\n\n";
printf "dumping configuration...\n";
my $cmd = $SRCDIR."/bin/dump_snmpd_config.pl";
print "  snmp: ".`$cmd`."\n";
$cmd = $SRCDIR."/bin/dump_firewall.pl";
print "  firewall: ".`$cmd`."\n";
$cmd = $SRCDIR."/bin/dump_apache_config.pl";
print "  httpd: ".`$cmd`."\n";
printf "restarting services...";
print "  stopping snmp: ".`killall -TERM snmpd`;
print "  starting snmp: ".`$SRCDIR/etc/init.d/snmpd start`;
print "  stopping firewall: ".`$SRCDIR/etc/init.d/firewall stop`;
print "  starting firewall: ".`$SRCDIR/etc/init.d/firewall start`;
print "  stopping httpd: ".`$SRCDIR/etc/init.d/apache stop`;
sleep 5;
print "  starting httpd: ".`$SRCDIR/etc/init.d/apache start`;
system("clear");

exit 0;

sub change_host {
  system("clear");
  printf "Enter this hostname (fully qualified name or ip): ";
  my $hostname = <STDIN>;
  # TODO: Better validation of hostname
  ($hostname) = $hostname =~ m/\s*(\S+)\s*$/;
  my $sth =  $master_dbh->prepare("UPDATE slave SET hostname='$hostname' WHERE id=$HOSTID");
  $sth->execute() or die ("error in UPDATE");
  $sth->finish();
  $sth =  $master_dbh->prepare("UPDATE master SET hostname='$hostname'");
  $sth->execute() or die ("error in UPDATE");
  $sth->finish();
  return;
}

sub view_slaves {
  system("clear");
  my $sth =  $master_dbh->prepare("SELECT id, hostname, port, ssh_pub_key  FROM slave") or die ("error in SELECT");
  $sth->execute() or die ("error in SELECT");
  my $el=$sth->rows;
  printf "Slaves list: ($el element(s))\n";
  while (my $ref=$sth->fetchrow_hashref()) {
    printf $ref->{'id'}."-\t".$ref->{'hostname'}."\t\t".$ref->{'port'}."\n";
  #  printf "\t".$ref->{'ssh_pub_key'}."\n";
  }
  $sth->finish();
  printf "\n******\ntype any key to return to main menu";
  ReadMode 'cbreak';
  my $key = ReadKey(0);
  ReadMode 'normal';
  return;
}

sub delete_slave {
  system("clear");
  printf "Please enter slave id to delete: ";
  my $d_id = <STDIN>;
  ($d_id) = $d_id =~ m/\s*([1-9]\d*)\s*$/;

  my $sth =  $master_dbh->prepare("DELETE FROM slave WHERE id='$d_id'");
  if (! $sth->execute()) {
    printf "no slave deleted..\n";
  } else {
    printf "slave $d_id deleted.\n";
    $sth->finish();
  }
  printf "\n******\ntype any key to return to main menu";
  ReadMode 'cbreak';
  my $key = <stdin>;
  ReadMode 'normal';
  chomp($key);
  return;
}

sub add_slave {
  system("clear");
  printf "Enter slave ID (unique!): ";
  my $id = <STDIN>;
  ($id) = $id =~ m/\s*([1-9]\d*)\s*$/;
  printf "Enter slave hostname: ";
  my $hostname = <STDIN>;
  ($hostname) = $hostname =~ m/\s*(\S+)\s*$/;
  printf "Enter slave password: ";
  my $password = <STDIN>;
  ($password) = $password =~ m/\s*(\S.*\S?)\s*$/;
  my $port = 3307;
  # TODO: Verify that we're actually fetching the key...
  my $key = "";

  # TODO: Better verification of hostname back when it is asked instead of here
  if ( $hostname =~ /^[A-Z,a-z,0-9,\.,\_,\-]{1,200}$/) {
    my $sth =  $master_dbh->prepare("INSERT INTO slave (id, hostname, port, password, ssh_pub_key) VALUES('$id', '$hostname', '$port', '$password', '$key')");
    if (!$sth->execute()) {
      printf "Slave NOT added !\n";
    } else {
      printf "Slave $hostname added.\n";
      $sth->finish();
    }
  } else {
    printf "please enter a slave hostname !\n";
  }
  printf "\n******\ntype any key to return to main menu";
  ReadMode 'cbreak';
  $key = <STDIN>;
  ReadMode 'normal';
  return;
}

sub check_host {
  my $sth =  $master_dbh->prepare("SELECT hostname FROM slave WHERE id=$HOSTID") or die ("error in SELECT");
  $sth->execute() or die ("error in SELECT");
  if ($sth->rows != 1) {
    return 1;
  }
  my $ref=$sth->fetchrow_hashref();
  if ($ref->{'hostname'} =~ /127\.0\.0\.1/ || $ref->{'hostname'} =~ /localhost/) {
    return 1;
  }
  return 0;
}

sub set_as_slave {
  system("clear");
  printf "Enter master hostname: ";
  my $master = <STDIN>;
  ($master) = $master =~ m/\s*(\S+)\s*$/;
  printf "Enter master password: ";
  chomp($password);

  print "Syncing to master host (this may take a few minutes)... ";
  my $logfile = '/tmp/syncerror.log';
  unlink($logfile);
  my $resync = `$SRCDIR/bin/resync_db.sh -F $master $password 1>/dev/null 2>/tmp/syncerror.log`;
  if ( -s $logfile) {
    print "\n  ** ERROR ** ";
    my $ERRORLOG;
    if (open($ERRORLOG, '<', $logfile)) {
      while(<$ERRORLOG>) {
        if (m/Access denied/) {
          print "Access on master is denied. Please double check the master password and try again.\n";
          print "Press any key to continue...\n";
          ReadKey(0);
          return;
        }
        if (m/Can't connect to MariaDB server/) {
          print "Master server is not responsive. Make sure you ran this script on the master host first to advise it of this new slave.\n";
          print "  ** ERROR ** Also make sure there is not firewall blocking port TCP 3306 between this host and the master.\n";
          print "Press any key to continue...\n";
          ReadKey(0);
          return;
        }
      }
      close($ERRORLOG);
    }
    print "Unknown error !\n";
    print "Check the master hostname or IP address, DNS resolution and that this script has been run on the master first.\n";
    ReadKey(0);
    return;
  }
  print "done.\n";

  # TODO: We should (and may) have a library to update these values rather than creating a shell
  `perl -pi -e 's/ISMASTER = Y/ISMASTER = N/' /etc/spamtagger.conf`;
  `perl -pi -e 's/(.*collect_rrd.*)/#\$1/' /var/spool/cron/crontabs/root`;
  `crontab /var/spool/cron/crontabs/root 2>&1`;
  print "Host is now a slave of $master\n";
  sleep 5;
  return;
}
