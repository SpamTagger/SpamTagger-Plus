#! /usr/bin/env perl
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

use v5.40;
use warnings;
use utf8;

use lib '/usr/spamtagger/lib';
use DB();
use Net::SMTP;
use ReadConfig;

our $config = ReadConfig::get_instance();
our $VARDIR = $config->get_option('VARDIR');
our $CLIENTID = $config->get_option('CLIENTID');

my $exim_id   = shift;
my $to_local  = shift;
my $to_domain = shift;
my $sender    = shift;
my $to        = $to_local . "@" . $to_domain;

my $test_address_mode =
  0;    # if we want to test the address before putting a spam in quarantine

my $msg = "";

my $store_id = $config->get_option('HOSTID');

my $DEBUG = 0;

## just log the spam in exim log
printf "spam detected for user: $to, from: $sender, with id: $exim_id => ";

my $start_msg      = 0;
my $line           = "";
my $has_forced_tag = 0;
my $is_bounce      = 0;
my $header_from    = "";
my $has_subject    = 0;
my $subject        = "";
my $score          = "unknown";
my $bounced_add    = "";
while (<>) {

  # just to remove garbage line before the real headers
  if ( $start_msg != 1 && /^[A-Z][a-z]*\:\ .*/ ) {
    $start_msg = 1;
  }

  $line = $_;

  # parse if message is forced
  if (/^X\-SpamTagger\:\ message\ forced\ $CLIENTID$/i) {
    $has_forced_tag = 1;
    next;
  }

  # parse if it is a bounce
  if (/^X\-SpamTagger\-Bounce\:\ /i) {
    $is_bounce = 1;
    next;
  }

  # parse for from
  if (/^From:\s+(.*)$/i) {
    $header_from = $1;
  }

  # parse for subject
  if ( $has_subject < 1 ) {
    if (/^Subject:\s+(\{ST_SPAM\}\s+)?(.*)/i) {
      if ( defined($2) ) {
        $subject = $2;
      } else {
        $subject = $1;
      }

      # we have to remove the spam tag first
      chomp($subject);
      $line = "Subject: $subject\n";

      if ($subject) {
        $has_subject = 1;
      }
    }
  }

  # parse for score
  if (/^X-SpamTagger-SpamCheck:.*\(.*score=(\S+)\,/) {
    $score = $1;
  }

  if ( $start_msg > 0 ) {

    # save the message in a variable
    $msg = $msg . $line;
    if ( $is_bounce > 0 ) {
      if ( $line =~ /^\s+\<?([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)\>?\s+$/ ) {
        $bounced_add = $1;
      } elsif ( $line =~ /Final-Recipient: rfc822; \<?([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)\>?/ ) {
        $bounced_add = $1;
      }
    }
  }
}

$to_domain = clean($to_domain);
$to_local  = clean($to_local);
$sender    = clean($sender);
if ( $is_bounce > 0 ) {
  $sender = "*";
  if ( $bounced_add !~ /^$/ ) {
    $sender .= "(" . clean($bounced_add) . ") ";
  } else {
    $sender .= clean($header_from);
  }
}
$exim_id = clean($exim_id);
$subject = clean($subject);

## connect to local slave configuration database as we need it a lot of time from now
our $config_dbh = DB->db_connect('slave', 'st_config');
$config_dbh->{mysql_auto_reconnect} = 1;

my $delivery_type = get_delivery_type();
if ( $delivery_type == 2 ) {
  print "want quarantine";
  if ( !put_in_quarantine() ) {
    print " ** could not put in quarantine!";
    send_anyway();
  }
} elsif ( $delivery_type == 3 ) {
  print "want drop";
} else {
  print "want tag";
  send_anyway();
}

$config_dbh->db_disconnect();

exit 0;

##########################################

sub send_anyway {
  my $smtp;

  my $tag = get_tag_prefs();
  if ( $tag =~ /\-1/ ) {
    $tag = "{Spam?}";
  }

  if ( $tag !~ /^$/ ) {
    $msg =~ s/Subject:\ /Subject: $tag /i;
  }

  unless ( $smtp = Net::SMTP->new('localhost:2525') ) {
    print " ** cannot connect to outgoing smtp server !\n";
    exit 0;
  }

  my $err = 0;
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) { panic_log_msg(); return; }

  #$smtp->debug(3);
  if ( $is_bounce > 0 ) {
    $smtp->mail($bounced_add);
  } else {
    $smtp->mail($sender);
  }
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) { panic_log_msg(); return; }
  $smtp->to($to);
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) { panic_log_msg(); return; }
  $smtp->data();
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) { panic_log_msg(); return; }
  $smtp->datasend($msg);
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) { panic_log_msg(); return; }
  $smtp->dataend();
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) { panic_log_msg(); return; }
  return;
}

##########################################

sub get_tag_prefs {
  get_pref( 'spam_tag', '{Spam?}', 0 );
  return;
}

##########################################

sub get_delivery_type {
  # delivery types are: 1=tag, 2=quarantine, 3=drop, default is tag
  get_pref( 'delivery_type', 1, 0 );
  return;
}

##########################################

sub get_pref ($pref, $default, $verbose) {
  if ( defined $config_dbh ) {
    my $sth =
      $config_dbh->prepare(
"SELECT p.$pref FROM email e, user_pref p WHERE e.pref=p.id AND e.address='$to'"
      )
      or return $default;
    $sth->execute() or return $default;

    if ( $sth->rows < 1 ) {
      $sth->finish();
      $sth = $config_dbh->prepare(
        "SELECT p.$pref FROM domain d, domain_pref p WHERE d.prefs=p.id
        AND ( d.name='$to_domain' or d.name='*') order by name DESC LIMIT 1"
      ) or return $default;
      $sth->execute() or return $default;
      if ( $sth->rows < 1 ) {
        return $default;
      }
      my $ref = $sth->fetchrow_hashref() or return $default;
      my $res = $ref->{$pref};
      $sth->finish();
      if ($verbose) { print "domain " }
      return $res;
    }
    my $ref = $sth->fetchrow_hashref() or return $default;
    my $res = $ref->{$pref};
    $sth->finish();
    if ($verbose) { print "user " }
    return $res;
  }
  if ($verbose) { print "no pref " }
  return $default;
}

##########################################

sub put_in_quarantine {
  if ( $test_address_mode > 0 ) {
    if ( no_such_address( $to, $to_domain ) ) {
      print " no such address - not putting in quarantine";
      return 1;
    }
  }
  if ( !-d "$VARDIR/spam/$to_domain" ) {
    mkdir( "$VARDIR/spam/$to_domain" );
  }
  if ( !-d "$VARDIR/spam/$to_domain/$to" ) {
    mkdir( "$VARDIR/spam/$to_domain/$to" );
  }

  ## save the spam file
  my $filename =
    $VARDIR . "/spam/" . $to_domain . "/" . $to . "/" . $exim_id;
  my $MSGFILE;
  unless (open($MSGFILE, ">", $filename ) ) {
    print " cannot open quarantine file $filename for writing";
    return 0;
  }
  print $MSGFILE $msg;
  close $MSGFILE;

  if ( $store_id < 0 ) {
    print " error, store id less than 0 ";
    return 0;
  }

  ## log in masters db
  my $in_master = 1;
  if ( defined $config_dbh ) {
    my $master_sth =
      $config_dbh->prepare("SELECT hostname, port, password FROM master")
      or return 0;
    $master_sth->execute() or return 0;
    if ( $master_sth->rows < 1 ) {
      $in_master = 0;
    }
    while ( my $master_ref = $master_sth->fetchrow_hashref() ) {
      if (
        !log_in_master(
          $master_ref->{'hostname'}, $master_ref->{'port'},
          $master_ref->{'password'}
        )
        )
      {
        $in_master = 0;
      }
    }
    $master_sth->finish();
  }

  ## log in slave (local)
  if ( !log_in_slave($in_master) ) {
    return 0;
  }

  return 1;
}

##########################################
sub no_such_address ($to, $domain) {
  if ( -d "$VARDIR/spam/$to_domain/$to" ) {
    return 0;
  }

  my $sth = $config_dbh->prepare(
    "SELECT d.destination FROM domain d, domain_pref p WHERE d.prefs=p.id
    AND ( d.name='$to_domain' OR d.name='*' ) order by name DESC LIMIT 1"
  ) or return 0;
  $sth->execute() or return 0;
  if ( $sth->rows < 1 ) {
    $sth->finish();
    return 1;
  }
  my $ref  = $sth->fetchrow_hashref();
  my $dest = $ref->{'destination'};
  $sth->finish();

  if ( $dest =~ /^$/ ) {
    return 0;
  }

  my $smtp = Net::SMTP->new($dest) or return 0;
  $smtp->mail("test\@localhost") or return 0;
  $smtp->to($to);
  my $err = $smtp->code();
  if ( ( $err == 550 ) ) {
    $smtp->close();
    return 1;
  }
  $smtp->close();
  return 0;
}

##########################################

sub log_in_master ($host, $port, $password) {
  my $master_dbh = DB->db_connect('master', 'st_spool');
  $master_dbh->{mysql_auto_reconnect} = 1;

  my $table = "misc";
  if ( $to_local =~ /^([a-z,A-Z])/ ) {
    $table = lc($1);
  } elsif ( $to_local =~ /^[0-9]/ ) {
    $table = 'num';
  } else {
    $table = 'misc';
  }
  my $query =
    "INSERT IGNORE INTO spam_$table (date_in, time_in, to_domain, to_user, sender, exim_id, M_score, M_subject, forced, in_master, store_slave)
    VALUES (NOW(), NOW(), '$to_domain', '$to_local', '$sender', '$exim_id', '$score', '$subject', '0', '1', $store_id)";
  my $master_sth = $master_dbh->prepare($query) or return 0;
  $master_sth->execute() or return 0;
  $master_sth->finish()  or return 0;
  $master_dbh->db_disconnect();

  return 1;
}

##########################################

sub log_in_slave ($in_master) {

  my $slave_dbh = DB->db_connect('slave', 'st_spool') or return 0;
  $slave_dbh->{mysql_auto_reconnect} = 1;

  my $table = "misc";
  if ( $to_local =~ /^([a-z,A-Z])/ ) {
    $table = lc($1);
  } elsif ( $to_local =~ /^[0-9]/ ) {
    $table = 'num';
  } else {
    $table = 'misc';
  }
  my $query =
    "INSERT IGNORE INTO spam_$table (date_in, time_in, to_domain, to_user, sender, exim_id, M_score, M_subject, forced, in_master, store_slave)
    VALUES (NOW(), NOW(), '$to_domain', '$to_local', '$sender', '$exim_id', '$score', '$subject', '0', '$in_master', $store_id)";

  my $slave_sth = $slave_dbh->prepare($query) or return 0;
  $slave_sth->execute() or return 0;
  $slave_sth->finish()  or return 0;
  $slave_dbh->db_disconnect();

  return 1;
}

##########################################

sub panic_log_msg {
  my $filename = $VARDIR."/spool/exim_stage4/paniclog/".$exim_id;
  print " **WARNING, cannot send message ! saving mail to: $filename\n";

  my $PANICLOG;
  open($PANICLOG, ">", $filename) or return;
  print $PANICLOG $msg;
  close $PANICLOG;
  return;
}
##########################################

sub clean ($str) {
  $str =~ s/\\/\\\\/g;
  $str =~ s/\'/\\\'/g;

  return $str;
}
