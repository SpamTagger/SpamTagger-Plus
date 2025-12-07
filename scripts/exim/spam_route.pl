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
use Net::SMTP();
use Time::HiRes qw(gettimeofday tv_interval);
my $stime = [gettimeofday];
use DB();
use SpamLogger();
use Email();
use ReadConfig;

my $config = ReadConfig::get_instance();
our $VARDIR = $config->get_option('VARDIR');

### Global variables
my $msg             = "";
my $DEBUG           = 0;
my $is_bounce       = 0;
my $header_from     = "";
my $subject         = "";
my $score           = "unknown";
my $rbls            = "";
my $prefilters      = "";
my $bounced_add     = "";
my $spam_type       = 'ST_SPAM';
my $store_id        = $config->get_option('HOSTID');
my @rbl_tags        = ('SBL\+XBL', 'SPAMHAUS-ZEN', 'spamcop.net', 'NJABL', 'SORBS-DNSBL', 'RFC-Ignorant', 'CompleteWhois', 'AHBL', 'SORBS-DUL', 'DSBL', 'SECURITYUSAGE');
my @prefiltertags   = ('MailFilter', 'NiceBayes', 'PreRBLs', 'Spamc', 'ClamSpam');
my %prefilterscores = ('Mailfilter' => 3, 'NiceBayes' => 3, 'PreRBLs' => 3, 'ClamSpam' => 4);
my @filters         = ('SpamAssassin');
my $globalscore     = 0;

### Global server variables
my $server_port = 12553;
my $debug = 0;

### Get parameters values
my $exim_id   = shift;
my $to_local  = shift;
my $to_domain = shift;
my $sender    = shift;
my $to        = $to_local . "@" . $to_domain;

## print something to Exim's log to say we are here
printf "spam detected for user: $to, from: $sender, with id: $exim_id => ";

## fetch values in message and store it in $msg
parse_input_message();
clean_variables();
my $ptime = tv_interval ($stime);

## get user preference
my $email = Email->new($to);
## check what to do with message
my $delivery_type = $email->get_pref( 'delivery_type', 1);
my $wantlisted = $email->has_in_want_warn_list('wantlist', $sender);
#print "\nin wantlist returned: $wantlisted\n";
my $warnlisted = $email->has_in_want_warn_list('warnlist', $sender);
#print "\nin warnlist returned: $warnlisted\n";
## if WANTLISTED, then go through, no tag
if ($wantlisted) {
  print " is wantlisted ($wantlisted) ";
  send_anyway($wantlisted);
} else {
  ## DROP
  if ( $delivery_type == 3 ) {
    print " want drop";
  ## if QUARANTINE but WARNLISTED, then send the warning
  } elsif ( $delivery_type == 2 && $warnlisted) {
    print " is warnlisted ($warnlisted) ";
    if ( !put_in_quarantine() ) {
      print " ** could not put in quarantine!";
      send_anyway(0);
    }
    if ( !$email->send_warnlist_hit($sender, $warnlisted, $exim_id) ) {
       print " ** could not send warning!";
       send_anyway(0);
    }
    send_notice();
  ## if QUARANTINE or BOUNCE then save message
  } elsif ($delivery_type == 2 || $is_bounce) {
    print " want quarantine";
    print " (bounce)" if ($is_bounce);
    if ( !put_in_quarantine() ) {
      print " ** could not put in quarantine!";
      send_anyway(0);
    }
  ## TAG
  } else {
    print " want tag";
    send_anyway(0);
  }
}

my $gtime = tv_interval ($stime);
print " (".(int($ptime*100)/100)."s/".(int($gtime*100)/100)."s)";
exit 0;

######################################
## sub functions
######################################

#####
## parse_input_message
#####
sub parse_input_message {
  my $start_msg      = 0;
  my $line           = "";
  my $has_subject    = 0;
  my $in_score       = 0;
  while (<>) {

    # just to remove garbage line before the real headers
    if ( $start_msg != 1 && /^[A-Z][a-z]*\:\ .*/ ) {
      $start_msg = 1;
    }

    $line = $_;

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
      if (/^Subject:\s+(\{(ST_SPAM|ST_HIGHSPAM)\}\s+)?(.*)/i) {
        if ( defined($3) ) {
          $subject = $3;
          $spam_type = $2;
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


    if (/^\S+:/) {
      $in_score = 0;
    }
    # parse for scores
    if (/^X-SpamTagger-SpamCheck:/ || $in_score) {
      $in_score = 1;
      if (/^X-SpamTagger-SpamCheck: (?:spam|not spam)?(.*)$/ || /^\s+(.*)/) {
        my @tags = split(/[,()]/, $1);
        foreach my $tag (@tags) {
          $tag =~ s/^\s+//g;
          $tag =~ s/\s+$//g;
          foreach my $rbltag (@rbl_tags) {
            if ($tag =~ m/^$rbltag/) {
              $rbls .= ", $rbltag";
            }
          }
          foreach my $pretag (@prefiltertags) {
            if ($tag =~ m/^$pretag/) {
              $prefilters .= ", $pretag";
              if (defined($prefilterscores{$pretag})) {
                $globalscore += $prefilterscores{$pretag};
              }
            }
          }
          if ($tag =~ m/^score=(\S+)/) {
            $score = $1;
          }
        }
      }
    }
    # parse for score
    if (/^X-SpamTagger-SpamCheck:.*\(.*score=(\S+)\,/) {
      $score = $1;
      if (int($score) >= 5) { $globalscore++; }
      if (int($score) >= 7) { $globalscore++; }
      if (int($score) >= 10) { $globalscore++; }
      if (int($score) >= 15) { $globalscore++; }
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

  $prefilters =~ s/^\s*,\s*//g;
  $rbls =~ s/^\s*,\s*//g;
  return;
}

#####
## clean_variables
#####
sub clean_variables {
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
  return;
}

#####
## send_anyway
#####
sub send_anyway ($wantlisted) {
  my $smtp;

  my %level = (1 => 'system', 2 => 'domain', 3 => 'user');

  if (! $wantlisted) {
    my $tag = $email->get_pref( 'spam_tag', '{Spam?}');
    $tag = "{Spam?}" if ( $tag =~ /\-1/ );
    $msg =~ s/Subject:\ /Subject: $tag /i if ( $tag !~ /^$/);
  } else {
    $msg =~ s/X-SpamTagger-SpamCheck: spam,/X-SpamTagger-SpamCheck: spam, wantlisted by $level{$wantlisted},/i;
  }

  unless ( $smtp = Net::SMTP->new('localhost:2525') ) {
    print " ** cannot connect to outgoing smtp server !\n";
    exit 0;
  }
  my $err = 0;
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    panic_log_msg();
    return;
  }

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

  send_notice() if ($wantlisted);
  return;
}

##########################################

sub put_in_quarantine {

  if ( !-d "$VARDIR/spam/$to_domain" ) {
    mkdir( "$VARDIR/spam/$to_domain" );
  }
  if ( !-d "$VARDIR/spam/$to_domain/$to" ) {
    mkdir( "$VARDIR/spam/$to_domain/$to" );
  }

  ## save the spam file
  my $filename = "$VARDIR/spam/$to_domain/$to/$exim_id";
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

  my $logger = SpamLogger->new("Client", "etc/exim/spamlogger.conf");
  my $res = $logger->log_spam($exim_id, $to_local, $to_domain, $sender, $subject, $score, $rbls, $prefilters, $globalscore);
  chomp($res);
  if ($res !~ /LOGGED BOTH/) {
    print " WARNING, logging is weird ($res)";
  }
  return 1;
}

##########################################
sub send_notice {
  if (defined($email) && defined($email->{d}) && $email->{d}->get_pref('notice_wwlists_hit') == 1) {
    $email->send_ww_hit_notice($wantlisted, $warnlisted, $sender, \$msg);
  }
  return;
}

##########################################

sub panic_log_msg {
  my $filename = $VARDIR . "/spool/exim_stage4/paniclog/" . $exim_id;
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
