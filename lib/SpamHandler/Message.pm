#!/usr/bin/env perl
#
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2004-2014 Olivier Diserens <olivier@diserens.ch>
#   Copyright (C) 2015-2017 Florian Billebault <florian.billebault@gmail.com>
#   Copyright (C) 2015-2017 Mentor Reka <reka.mentor@gmail.com>
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
#   This module will just read the configuration file

package SpamHandler::Message;

use v5.40;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = ();
our $VERSION   = 1.0;

use lib "/usr/spamtagger/lib/";
use Email();
use ReadConfig();
use Net::SMTP();
use File::Path qw(mkpath);
use Time::HiRes qw(gettimeofday tv_interval);
use threads();

sub new ($class, $id, $daemon, $batchid) {
  my $t   = threads->self;
  my $tid = $t->tid;
  my %timers;

  my $this = {
    daemon             => $daemon,
    batchid            => $batchid,
    threadid           => $tid,
    id                 => $id,
    envfile            => $id . ".env",
    msgfile            => $id . ".msg",
    exim_id            => '',
    env_sender         => '',
    env_rcpt           => '',
    env_domain         => '',
    envtolocal         => '',
    bounce             => 0,
    bonced_add         => '',
    msg_from           => '',
    msg_date           => '',
    msg_subject        => '',
    sc_nicebayes       => 0,
    sc_spamc           => 'NULL',
    sc_newsl           => 0,
    sc_prerbls         => 0,
    sc_clamspam        => 0,
    sc_trustedsources  => 0,
    sc_urirbls         => 0,
    sc_machinelearning => 0,
    sc_global          => 0,
    prefilters         => '',

    decisive_module => {
      module => undef,
      position => 100,
      action => undef
    },

    quarantined => 0,

    fullmsg   => '',
    fullheaders => '',
    fullbody  => '',

    %timers => (),
  };

  $this->{headers} = {};

  $this->{accounting} = undef;
  my $accounting = "MailScanner::Accounting";
  if (eval { "require $accounting" }) {
    $this->{accounting} = $accounting->new('post');
  }

  if ( $this->{id} =~ m/^([A-Za-z0-9]{6}-[A-Za-z0-9]{6,11}-[A-Za-z0-9]{2,4})/ ) {
    $this->{exim_id} = $1;
  }

  return bless $this, $class;
}

sub load ($this) {
  $this->start_timer('Message load');
  if ( -f $this->{envfile} ) {
    ## open env file
    $this->start_timer('Message envelope load');
    $this->load_env_file();
    $this->end_timer('Message envelope load');
  } else {
    $this->{daemon}->do_log(
      $this->{batchid} . ": "
        . $this->{id}
        . " No enveloppe file found !",
      'spamhandler'
    );
    return 0;
  }

  if ( -f $this->{msgfile} ) {
    ## open msg file
    $this->start_timer('Message body load');
    $this->load_msg_file();
    $this->end_timer('Message body load');
  } else {
    $this->{daemon}->do_log(
      $this->{batchid} . ": " . $this->{id} . " No message file found !",
      'spamhandler', 'debug'
    );
    return 0;
  }

  $this->{daemon}->do_log(
    $this->{batchid} . ": " . $this->{id} . " message loaded",
    'spamhandler', 'debug'
    );
  $this->end_timer('Message load');
  return;
}

sub process ($this) {
  $this->start_timer('Message processing');
  my $email = Email::create( $this->{env_rcpt} );
  return 0 if !$email;

  my $status;

  ## check what to do with message

  # If uncheckable (consumed licenses, etc. don't filter
  if ( defined($this->{accounting}) && !$this->{accounting}->check_checkeable_user( $this->{env_rcpt} ) ) {
    $status = $this->{accounting}->get_last_message();
    $this->manage_uncheckeable($status);

  # Otherwise get policies and determine action
  } else {
    $this->start_timer('Message fetch prefs');
    my $delivery_type = int( $email->get_pref( 'delivery_type', 1 ) );
    $this->end_timer('Message fetch prefs');
    $this->start_timer('Message fetch ww');

    # Policies
    my $wantlisted;
  # if the flag file to activate wantlist also on msg_from is there
  if ( -e '/var/spamtagger/spool/spamtagger/st-wl-on-both-from') {
  $wantlisted = (
     $email->has_in_want_warn_list( 'wantlist', $this->{env_sender} ) ||
    $email->has_in_want_warn_list( 'wantlist', $this->{msg_from} )
  );
  # else wantlists are only applied to SMTP From
  } else {
  $wantlisted = $email->has_in_want_warn_list( 'wantlist', $this->{env_sender} );
  }
    my $warnlisted;
  if ( -e '/var/spamtagger/spool/spamtagger/st-wl-on-both-from') {
  $warnlisted = (
    $email->has_in_want_warn_list( 'warnlist', $this->{env_sender} ) ||
    $email->has_in_want_warn_list( 'warnlist', $this->{msg_from} )
  );
  } else {
  $warnlisted = $email->has_in_want_warn_list( 'warnlist', $this->{env_sender} );
  }
    my $blocklisted =
      $email->has_in_want_warn_list( 'blocklist', $this->{env_sender} ) || $email->has_in_want_warn_list( 'blocklist', $this->{msg_from});
    my @level = ('NOTIN','System','Domain','User');
    $this->{nwantlisted} =
      $email->loaded_is_ww_listed( 'wnews', $this->{msg_from} ) || $email->loaded_is_ww_listed( 'wnews', $this->{env_sender} );
    $this->{news_allowed} = $email->get_pref('allow_newsletters') || 0;
    $this->end_timer('Message fetch ww');

    # Action

    ## Wantlist
    if ($wantlisted) {

      ## Newsletter
      if ( $this->{sc_newsl} >= 5 ) {
        if ($this->{news_allowed}) {
          $status = "is desired (Newsletter) and wantlisted by " . $level[$wantlisted];
          $this->{decisive_module}{module} = undef;
          $this->manage_wantlist($wantlisted,3);
        } elsif ($this->{nwantlisted}) {
          $status = "is newslisted by " . $level[$this->{nwantlisted}] . " and wantlisted by " . $level[$wantlisted];
          $this->{decisive_module}{module} = undef;
          $this->manage_wantlist($wantlisted,$this->{nwantlisted});
        } else {
          $status = "is wantlisted by " . $level[$wantlisted] . " but newsletter";
          $this->{decisive_module}{module} = 'Newsl';
          if ( $delivery_type == 1 ) {
            $status .= ": want tag";
            $this->{fullheaders} =~
              s/(.*Subject:\s+)(\{(ST_SPAM|ST_HIGHSPAM)\})?(.*)/$1\{ST_SPAM\}$4/i;
            my $tag = $email->get_pref( 'spam_tag', '{Spam?}' );
            $this->manage_tag_mode($tag);
          } elsif ( $warnlisted ) {
            $status .= ": warn";
            $this->{decisive_module}{module} = 'warnlisted';
            $this->quarantine();
            my $id =
              $email->send_warnlist_hit( $this->{env_sender}, $warnlisted, $this->{exim_id} );
            if ($id) {
              $this->{daemon}->do_log(
                $this->{batchid}
                  . ": message "
                  . $this->{exim_id}
                  . " warn message ready to be delivered with new id: "
                  . $id,
                'spamhandler', 'info'
              );
            } else {
              $this->{daemon}->do_log(
                $this->{batchid}
                  . ": message "
                  . $this->{exim_id}
                  . " warn message could not be delivered.",
                'spamhandler', 'error'
              );
            }
          } elsif ( $delivery_type == 3 ) {
            $status .= ": want drop";
          } elsif ( $this->{bounce} ) {
            $status .= ": (bounce)";
            $this->quarantine();
          } else {
            $status .= ": want quarantine";
            $this->quarantine();
          }
        }

      ## Not Newsletter
      } else {
        $status = "is wantlisted ($wantlisted)";
        $this->{decisive_module}{module} = undef;
        $this->manage_wantlist($wantlisted);
      }
    ## Blocklist
  } elsif ($blocklisted) {
      $status = "is blocklisted ($blocklisted)";
      $this->manage_blocklist($blocklisted);
      $this->{decisive_module}{module} = 'blocklisted';
      if ($delivery_type == 1) {
        $status .= ": want tag";
        my $tag = $email->get_pref( 'spam_tag', '{Spam?}' );
        $this->manage_tag_mode($tag);
      } elsif ( $warnlisted ) {
        $status .= ": warn";
        $this->{decisive_module}{module} = 'warnlisted';
        $this->quarantine();
        my $id =
          $email->send_warnlist_hit( $this->{env_sender}, $warnlisted, $this->{exim_id} );
        if ($id) {
          $this->{daemon}->do_log(
            $this->{batchid}
              . ": message "
              . $this->{exim_id}
              . " warn message ready to be delivered with new id: "
              . $id,
            'spamhandler', 'info'
          );
        } else {
          $this->{daemon}->do_log(
            $this->{batchid}
              . ": message "
              . $this->{exim_id}
              . " warn message could not be delivered.",
            'spamhandler', 'error'
          );
        }
      } elsif ( $delivery_type == 3 ) {
        $status .= ": want drop";
      } elsif ( $this->{bounce} ) {
        $status .= ": (bounce)";
        $this->quarantine();
      } else {
        $status .= ": want quarantine";
        $this->quarantine();
      }


    ## Spam
    } elsif ( defined $this->{decisive_module}{module} && $this->{decisive_module}{action} eq 'positive' ) {

      # Is spam, and no warnlist
      $status = "is spam";
      if ( $delivery_type == 1 ) {
        $status .= ": want tag";
        my $tag = $email->get_pref( 'spam_tag', '{Spam?}' );
        $this->manage_tag_mode($tag);
      } elsif ( $warnlisted ) {
        $status .= ": warn";
        $this->{decisive_module}{module} = 'warnlisted';
        $this->quarantine();
        my $id =
          $email->send_warnlist_hit( $this->{env_sender}, $warnlisted, $this->{exim_id} );
        if ($id) {
          $this->{daemon}->do_log(
            $this->{batchid}
              . ": message "
              . $this->{exim_id}
              . " warn message ready to be delivered with new id: "
              . $id,
            'spamhandler', 'info'
          );
        } else {
          $this->{daemon}->do_log(
            $this->{batchid}
              . ": message "
              . $this->{exim_id}
              . " warn message could not be delivered.",
            'spamhandler', 'error'
          );
        }
      } elsif ( $delivery_type == 3 ) {
        $status .= ": want drop";
      } elsif ( $this->{bounce} ) {
        $status .= ": (bounce)";
        $this->quarantine();
      } else {
        $status .= ": want quarantine";
        $this->quarantine();
      }

    ## Newsletter
    } elsif ($this->{sc_newsl} >= 5 ) {
      if ($email->get_pref('allow_newsletters')) {
        $status = "is desired (Newsletter)";
        $this->{decisive_module}{module} = undef;
        $this->manage_wantlist(undef,3);
      } elsif ($this->{nwantlisted}) {
        $status = "is newslisted by " . $level[$this->{nwantlisted}];
        $this->{decisive_module}{module} = undef;
        $this->manage_wantlist(undef,$this->{nwantlisted});
      } else {
        $status = "is newsletter";
        $this->{decisive_module}{module} = 'Newsl';
        if ( $delivery_type == 1 ) {
          $status .= ": want tag";
          $this->{fullheaders} =~
            s/(.*Subject:\s+)(\{(ST_SPAM|ST_HIGHSPAM)\})?(.*)/$1\{ST_SPAM\}$4/i;
          my $tag = $email->get_pref( 'spam_tag', '{Spam?}' );
          $this->manage_tag_mode($tag);
        } elsif ( $warnlisted ) {
          $status .= ": warn";
          $this->{decisive_module}{module} = 'warnlisted';
          $this->quarantine();
          my $id =
            $email->send_warnlist_hit( $this->{env_sender}, $warnlisted, $this->{exim_id} );
          if ($id) {
            $this->{daemon}->do_log(
              $this->{batchid}
                . ": message "
                . $this->{exim_id}
                . " warn message ready to be delivered with new id: "
                . $id,
              'spamhandler', 'info'
            );
          } else {
            $this->{daemon}->do_log(
              $this->{batchid}
                . ": message "
                . $this->{exim_id}
                . " warn message could not be delivered.",
              'spamhandler', 'error'
            );
          }
        } elsif ( $delivery_type == 3 ) {
          $status .= ": want drop";
        } elsif ( $this->{bounce} ) {
          $status .= ": (bounce)";
          $this->quarantine();
        } else {
          $status .= ": want quarantine";
          $this->quarantine();
        }
      }

    # Neither newsletter, nor spam
    } else {
      $status = 'not spam';
      unless ($this->{decisive_module}{action} eq 'negative') {
        $this->{decisive_module}{module} = undef;
      }
      $this->{fullheaders} =~ s/Subject:\s+\{(ST_SPAM|ST_HIGHSPAM)\}/Subject:/i;
      $this->send_me_anyway();
    }
  }

  my $log = $this->{batchid}
    . ": message "
    . $this->{exim_id} . " R:<"
    . $this->{env_rcpt} . "> S:<"
    . $this->{env_sender}
    . "> status "
    . $status;
  if (defined $this->{decisive_module}{module}) {
    $log .= ", module: ".$this->{decisive_module}{module};
  }
  ## log status and finish
  $this->{daemon}->do_log($log, 'spamhandler', 'info');
  $this->end_timer('Message processing');
  $this->start_timer('Message deleting');
  $this->delete_files();
  $this->end_timer('Message deleting');
  return 1;
}

sub load_env_file ($this) {
  my $env;
  open($env, '<', $this->{envfile} ) or return 0;

  my $fromfound = 0;
  while (<$env>) {
    if ( !$fromfound ) {
      $fromfound = 1;
      $this->{env_sender} = lc($_);
      chomp( $this->{env_sender} );
    } else {
      if (/([^\s]+)/) { # untaint
        $this->{env_rcpt} = lc($1);
        chomp( $this->{env_rcpt} );
        }
    }
  }
  close $env;

  if ( $this->{env_rcpt} =~ m/^(\S+)@(\S+)$/ ) {
    $this->{env_tolocal} = $1;
    $this->{env_domain}  = $2;
  }
  return;
}

sub load_msg_file ($this) {
  my $has_subject = 0;
  my $in_score  = 0;
  my $in_header   = 1;
  my $last_header = '';
  my $last_hvalue = '';
  my $uriscount   = 0;

  my $BODY;
  open($BODY, '<', $this->{msgfile} ) or return 0;
  while (<$BODY>) {

    ## check for end of headers
    if ( $in_header && /^\s*$/ ) {
      $in_header = 0;
    }

    ## parse for headers
    if ($in_header) {
      ## found a new header
      if (/^([A-Za-z]\S+):\s*(.*)/) {
        $last_header = lc($1);
        $this->{headers}{$last_header} .= $2;
      }
      ## found a new line in multi-line header
      if (/^\s+(.*)/) {
        $this->{headers}{$last_header} .= $1;
      }
      $this->{fullheaders} .= $_;
    ## parse for body
    } else {
      $this->{fullbody} .= $_;

      ## try to find bounced address if this is a bounce
      if ( $this->{bounce} > 0 ) {
        if (/^\s+\<?([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)\>?\s+$/) {
          $this->{bounced_add} = $1;
        } elsif (/Final-Recipient: rfc822; \<?([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+)\>?/) {
          $this->{bounced_add} = $1;
        }
      }

      if ( $this->{daemon}->{reportrbls} && $uriscount <= $this->{daemon}->{maxurisreports} ) {
        my $uri = $this->{daemon}->{dnslists}->find_uri( $_, $this->{batchid} . ": " . $this->{id} );
        if ($uri) {
          $uriscount++;
          $uri = $uri . ".isspam";
          $this->{daemon}->{dnslists}->check_dns( $uri, 'URIRBL',
          $this->{batchid} . ": " . $this->{id} );
        }
        my $email = $this->{daemon}->{dnslists}->find_email( $_, $this->{batchid} . ": " . $this->{id} );
        if ($email) {
          $uriscount++;
          $email = $email . ".isspam";
          $this->{daemon}->{dnslists}->check_dns( $email, 'ERBL',
          $this->{batchid} . ": " . $this->{id} );
        }
      }
    }
  }
  close $BODY;

  ## check if message is a bounce
  if ( defined( $this->{headers}{'x-spamtagger-bounce'} ) ) {
    $this->{bounce} = 1;
  }
  ## check for standard (but untrusted) headers
  if ( defined( $this->{headers}{'from'} ) ) {
  if ( $this->{headers}{'from'} =~ m/<.*>/ ) {
  $this->{msg_from} = $this->{headers}{'from'};
  $this->{msg_from} =~ s/.*<([^>]*)>/$1/;
  } else {
  $this->{msg_from} = $this->{headers}{'from'};
  }
  }
  if ( defined( $this->{headers}{'date'} ) ) {
    $this->{msg_date} = $this->{headers}{'date'};
  }
  if ( defined( $this->{headers}{'subject'} ) ) {
    $this->{msg_subject} = $this->{headers}{'subject'};
  }

  $this->load_scores();
  return;
}

sub load_scores ($this) {
  unless ( defined( $this->{headers}{'x-spamtagger-spamcheck'} ) ) {
    %{$this->{decisive_module}} = (
      'module' => 'NOHEADER',
      'position' => 0,
      'action' => 'negative'
    );
    $this->{daemon}->do_log(
    $this->{batchid} . ": " . $this->{id} . " no spamcheck header",
      'spamhandler', 'warn'
    );
    return 0;
  }

  if ( defined( $this->{headers}{'x-spamtagger-status'} ) ) {
    if ( $this->{headers}{'x-spamtagger-status'} =~ /Blocklisted/ ) {
      $this->{prefilters} .= ", Blocklist";
    }
  }

  my $line = $this->{headers}{'x-spamtagger-spamcheck'};
  $this->{daemon}->do_log(
    $this->{batchid} . ": " . $this->{id} . " Processing spamcheck header: " . $line,
    'spamhandler', 'info'
  );

  if ( $line =~ /.*Newsl \(score=(\d+\.\d+),.*/ ) {
    $this->{sc_newsl} = $1;
    # Not processed as decisive module
    if ( $this->{sc_newsl} >= 5 )  {
      $this->{sc_global} += 1;
      $this->{prefilters} .= ", Newsl";
    }
  }

  if ( $line =~ /.*TrustedSources \(.*/ ) {
    $this->decisive_module('TrustedSources',$line);
    $this->{prefilters} .= ", TrustedSources";
  }

  if ( $line =~ /.*NiceBayes \(([\d.]+)%.*/ ) {
    $this->{sc_nicebayes} = $1;
    $this->decisive_module('NiceBayes',$line);
    $this->{sc_global} += 3;
    $this->{prefilters} .= ", NiceBayes";
  }

  if ( $line =~ /.*(Commtouch|MessageSniffer) \(([^\)]*)/ ) {
    if ($2 ne 'too big' && $2 !~ m/^0 \-.*/) {
      $this->decisive_module($1,$line);
      $this->{sc_global} += 3;
      $this->{prefilters} .= ", ".$1;
    }
  }

  if ( $line =~ /.*PreRBLs \(([^\)]*), ?position/ ) {
    my $rbls = scalar(split( ',', $1 ));
    $this->{sc_prerbls} = $rbls;
    $this->decisive_module('PreRBLs',$line);
    $this->{sc_global} += $rbls + 1;
    $this->{prefilters} .= ", PreRBLs";
  }

  if ( $line =~ /.*UriRBLs \(([^\)]*), ?position/ ) {
    my $rbls = scalar(split( ',', $1 ));
    $this->{sc_urirbls} = $rbls;
    $this->decisive_module('UriRBLs',$line);
    $this->{sc_global} += $rbls + 1;
    $this->{prefilters} .= ", UriRBLs";
  }

  if ( $line =~ /.*Spamc \(score=(\d+\.\d+),([^\)]*)\)/ ) {
    unless ($2 =~ m/, NONE,/) {
      $this->{sc_spamc} = $1;
      $this->decisive_module('Spamc',$line);
      if ( int( $this->{sc_spamc} ) >= 5 )  {
        $this->{sc_global}++;
        $this->{prefilters} .= ", SpamC";
      }
      if ( int( $this->{sc_spamc} ) >= 7 )  { $this->{sc_global}++; }
      if ( int( $this->{sc_spamc} ) >= 10 ) { $this->{sc_global}++; }
      if ( int( $this->{sc_spamc} ) >= 15 ) { $this->{sc_global}++; }
    }
  }

  if ( $line =~ /.*ClamSpam \(([^,]*),/ ) {
    $this->decisive_module('ClamSpam',$line);
    $this->{sc_clamspam} = $1;
    if ($1 ne 'too big') {
      $this->{sc_global} += 4;
    }
    $this->{prefilters} .= ", ClamSpam";
  }

  if ( $line =~ /.*MachineLearning \((not applied \()?([\d.]+)%.*/ ) {
    $this->decisive_module('MachineLearning',$line);
    $this->{sc_machinelearning} = $2;
    $this->{prefilters} .= ", MachineLearning";
  }

  if ( $line =~ /spam, / && !defined($this->{decisive_module}->{module}) ) {
    %{$this->{decisive_module}} = (
      'module' => 'Unknown',
      'position' => 0,
      'action' => 'positive'
    );
    $this->{prefilters} .= ", Unknown";
    $this->{daemon}->do_log(
      "$this->{exim_id} Flagged as spam, but unable to parse a recognized module: '$line', must quarantine to prevent loop at Stage 4.",
      'spamhandler', 'error'
    );
  }

  $this->{prefilters} =~ s/^, //;

  return 1;
}

sub delete_files ($this) {
  unlink( $this->{envfile} );
  unlink( $this->{msgfile} );
  $this->{daemon}->delete_lock( $this->{id} );
  return 1;
}

sub purge ($this) {
  delete( $this->{fullheaders} );
  delete( $this->{fullmsg} );
  delete( $this->{fullbody} );
  delete( $this->{headers} );
  foreach my $k ( keys %{$this} ) {
    $this->{$k} = '';
    delete $this->{$k};
  }
  return;
}

sub manage_uncheckeable ($this, $status) {
  ## modify the X-SpamTagger-SpamCheck header
  $this->{fullheaders} =~
    s/X-SpamTagger-SpamCheck: [^\n]+(\r?\n\s+[^\n]+)*/X-SpamTagger-SpamCheck: cannot be checked against spam ($status)/mi;

  ## remove the spam tag
  $this->{fullheaders} =~ s/Subject:\s+\{(ST_SPAM|ST_HIGHSPAM)\}/Subject:/i;

  $this->send_me_anyway();
  return 1;
}

sub manage_wantlist ($this, $wantlevel, $newslevel = undef) {
  my %level = ( 1 => 'system', 2 => 'domain', 3 => 'user' );
  my $str;
  if (defined($wantlevel)) {
    $str = "wantlisted by " . $level{$wantlevel};
    if (defined($newslevel)) {
      $str .= " and newslisted by " . $level{$newslevel};
    }
  } elsif (defined($newslevel)) {
    $str = "newslisted by " . $level{$newslevel};
  }

  ## modify the X-SpamTagger-SpamCheck header
  $this->{fullheaders} =~
    s/X-SpamTagger-SpamCheck: ([^,]*),/X-SpamTagger-SpamCheck: not spam, $str,/i;

  ## remove the spam tag
  $this->{fullheaders} =~ s/Subject:\s+\{(ST_SPAM|ST_HIGHSPAM)\}/Subject:/i;

  $this->send_me_anyway();
  return 1;
}

sub manage_blocklist ($this, $blocklevel) {
  my %level = ( 1 => 'system', 2 => 'domain', 3 => 'user' );
  my $str   = "blocklisted by " . $level{$blocklevel};

  $this->{fullheaders} =~
    s/(.*Subject:\s+)(\{(ST_SPAM|ST_HIGHSPAM)\})?(.*)/$1\{ST_SPAM\}$4/i;

  ## modify the X-SpamTagger-SpamCheck header
  $this->{fullheaders} =~
    s/X-SpamTagger-SpamCheck: ([^,]*),/X-SpamTagger-SpamCheck: spam, $str,/i;

  return 1;
}

sub manage_tag_mode ($this, $tag) {
  ## change the spam tag
  $this->{fullheaders} =~
    s/Subject:\s+\{(ST_SPAM|ST_HIGHSPAM)\}/Subject:$tag /i;

  $this->send_me_anyway();
  return 1;
}

sub send_me_anyway ($this) {
  $this->{daemon}->do_log(
    $this->{batchid}
      . ": message "
      . $this->{exim_id}
      . " Message will be delivered using SendMeAnyway",
    'spamhandler', 'info'
  );

  my $smtp;
  unless ( $smtp = Net::SMTP->new('localhost:2525') ) {
    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " ** cannot connect to outgoing smtp server !",
      'spamhandler', 'error'
    );
    return 0;
  }
  my $err = 0;
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    ## smtpError
    return 0;
  }

  #$smtp->debug(3);
  if ( $this->{bounce} > 0 ) {
    $smtp->mail( $this->{bounced_add} );
  } else {
    $smtp->mail( $this->{env_sender} );
  }
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    ## smtpError
    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " Could not set MAIL FROM",
      'spamhandler', 'error'
    );
    return 0;
  }
  $smtp->to( $this->{env_rcpt} );
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    ## smtpError
    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " Could not set RCPT TO",
      'spamhandler', 'error'
    );
    return;
  }
  $smtp->data();
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    ## smtpError

    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " Could not set DATA",
      'spamhandler', 'error'
    );
    return;
  }

  #print $this->getRaw_message();
  $smtp->datasend( $this->getRaw_message() );
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    ## smtpError
    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " Could not set DATA content",
      'spamhandler', 'error'
    );
    return;
  }
  $smtp->dataend();
  $err = $smtp->code();
  if ( $err < 200 || $err >= 500 ) {
    ## smtpError
    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " Could not set end of DATA (.)",
      'spamhandler', 'error'
    );
    return;
  }
  my $returnmessage = $smtp->message();
  my $id      = 'unknown';
  if ( $returnmessage =~ m/id=(\S+)/ ) {
    $id = $1;
  }

  if ($id eq 'unknown') {
    $this->{daemon}->do_log(
      $this->{batchid}
        . ": message "
        . $this->{exim_id}
        . " Could not deliver the classical way, had to force the dataend, cause was :"
        . $returnmessage,
      'spamhandler', 'info'
    );

      $smtp->rawdatasend('\n.\n');
         $smtp->dataend();

      $err = $smtp->code();
    if ( $err < 200 || $err >= 500 ) {
          ## smtpError
      $this->{daemon}->do_log(
        $this->{batchid}
          . ": message "
          . $this->{exim_id}
          . " Could not deliver the classical way, had to force the dataend ",
        'spamhandler', 'error'
      );
      return;
    }
    $returnmessage = $smtp->message();
    if ( $returnmessage =~ m/id=(\S+)/ ) {
      $id = $1;
    }
  }

  $this->{daemon}->do_log(
    $this->{batchid}
      . ": message "
      . $this->{exim_id}
      . " ready to be delivered with new id: "
      . $id,
    'spamhandler', 'info'
  );
  return 1;
}

sub get_raw_message ($this) {
  my $msg = $this->{fullheaders};
  $msg .= "\n";
  $msg .= $this->{fullbody};

  return $msg;
}

sub quarantine ($this) {
  $this->start_timer('Message quarantining');
  my $config = ReadConfig::get_instance();

  ## remove the spam tag
  $this->{fullheaders} =~ s/Subject:\s+\{(ST_SPAM|ST_HIGHSPAM)\}/Subject:/i;
  if ( $this->{headers}{subject} ) {
    $this->{headers}{subject} =~ s/^\S*\{(ST_SPAM|ST_HIGHSPAM)\}//i;
  } else {
    $this->{headers}{subject} = "";
  }
  if ( !-d $config->get_option('VARDIR') . "/spam/" . $this->{env_domain} ) {
    mkdir( $config->get_option('VARDIR') . "/spam/" . $this->{env_domain} );
  }
  if (  !-d $config->get_option('VARDIR') . "/spam/"
    . $this->{env_domain} . "/"
    . $this->{env_rcpt} )
  {
    mkpath(
      $config->get_option('VARDIR') . '/spam/'
        . $this->{env_domain} . '/'
        . $this->{env_rcpt},
      {error => \my $err}
    );
    if ($err && @$err) {
      for my $diag (@$err) {
        my ($file, $message) = %$diag;
        if ($file eq '') {
          $this->{daemon}->do_log('Batch : ' .$this->{batchid} . ' ; message : ' . $this->{exim_id} . " => general error: $message", 'spamhandler' );
        } else {
          $this->{daemon}->do_log('Batch : ' .$this->{batchid} . ' ; message : ' . $this->{exim_id} . " problem creating $file: $message", 'spamhandler' );
        }
      }
      exit 0;
    }
  }

  ## save the spam file
  my $filename =
    $config->get_option('VARDIR') . "/spam/"
      . $this->{env_domain} . "/"
      . $this->{env_rcpt} . "/"
      . $this->{exim_id};

  my $MSGFILE;
  unless (open($MSGFILE, ">", $filename ) ) {
    print " cannot open quarantine file $filename for writing";
    $this->{daemon}->do_log(
      "Cannot open quarantine file $filename for writing",
      'spamhandler', 'error'
    );
    return 0;
  }
  print $MSGFILE $this->get_raw_message();
  close $MSGFILE;

  $this->{quarantined} = 1;
  $this->end_timer('Message quarantining');

  return 1;
}

# TODO: SpamHandler::Message::do_log only used once in Batch.pm (as $msg->do_log).
# Since the actual logging here is done using the logger for the daemon, we should
# just be able to move the contents of this function to that place in Batch.pm
sub do_log ($this, $dbname, $insourceh) {
  return 1 if ( $this->{quarantined} < 1 );

  $this->start_timer('Message logging');
  my $loggedonce = 0;

  my %prepared = %{ $this->{daemon}->{prepared}{$dbname} };
  return 0 if ( !%prepared );

  ## find out correct table
  my $table = "misc";
  if ( $this->{env_tolocal} =~ /^([a-z,A-Z])/ ) {
    $table = lc($1);
  } elsif ( $this->{env_tolocal} =~ /^[0-9]/ ) {
    $table = 'num';
  }
  my $p = $prepared{$table};
  if ( !$p ) {
    $this->{daemon}
      ->do_log( "Error, could not get prepared statement for table: $table",
      'spamhandler', 'error' );
    return 0;
  }

  my $is_newsletter = ( $this->{sc_newsl} >= 5 && !$this->{nwantlisted} && !$this->{news_allowed}) || 0;

  my $res = $p->execute(
    $this->{env_domain}, $this->{env_tolocal},
    $this->{env_sender}, $this->{exim_id},
    $this->{sc_spamc},   $this->{sc_prerbls},
    $this->{prefilters}, $this->{headers}{subject},
    $this->{sc_global},  $$insourceh, $is_newsletter
  );
  if ( !$res ) {
    $this->{daemon}->do_log(
      "Error while logging msg "
        . $this->{exim_id}
        . " to db $dbname, retrying, if no further message, it's ok",
      'spamhandler', 'error'
    );
    $this->{daemon}->connect_databases();
    ## and try again
    $res = $p->execute(
      $this->{env_domain}, $this->{env_tolocal},
      $this->{env_sender}, $this->{exim_id},
      $this->{sc_spamc},   $this->{sc_prerbls},
      $this->{prefilters}, $this->{headers}{subject},
      $this->{sc_global},  $$insourceh, $is_newsletter
    );

    if ( !$res ) {
      $this->{daemon}->do_log(
        "Error while executing log query (msgid="
          . $this->{exim_id}
          . ", db=$dbname): "
          . $p->errstr,
        'spamhandler', 'error'
      );
      return 0;
    }
  } else {
    $loggedonce = 1;
  }
  $this->{daemon}->do_log(
    " Message " . $this->{exim_id} . " logged in database \"$dbname\"",
    'spamhandler', 'debug' );
  if ( $dbname eq 'realsource' ) {
    $$insourceh = 1;
  }
  $this->start_timer('Message logging');
  return $loggedonce;
}

sub decisive_module ($this, $module, $line) {
  $line =~ s/.*$module \((.*)/$1/;
  $line =~ s/decisive\).*/decisive/;
  my $position = my $decisive = $line;
  $decisive =~ s/.*, ?([^ ]*) decisive.*/$1/;
  $position =~ s/.*, ?position ?: ?(\d+).*/$1/;
  $this->{daemon}->do_log('Current decisive module is "'.$this->{decisive_module}{'module'}.'" with action "'.$this->{decisive_module}{'action'}.'" and position "'.$this->{decisive_module}{'position'}.'"','spamhandler', 'debug');
  if (!defined $decisive || !defined $position) {
    $this->{daemon}->do_log("Failed to discover decisive or position value for $module: $line", 'spamhandler', 'debug');
    return 0;
  }
  if ($position >= $this->{decisive_module}{position}) {
    $this->{daemon}->do_log("Found $module of lower priority $position, not updating decisive_module", 'spamhandler', 'debug');
  # If there is two modules of the same position (this would be a bug), then prefer the spam
  } elsif ( ($position == $this->{decisive_module}{position}) && ($decisive eq 'spam') ) {
    $this->{daemon}->do_log("Found positively decisive module $module of equal priority $position, updating decisive_module", 'spamhandler', 'debug');
    %{$this->{decisive_module}} = (
      'module' => $module,
      'position' => $position,
      'action' => 'positive'
    );
  } elsif ($decisive eq 'not') {
    $this->{daemon}->do_log("Found undecisive $module of priority $position, not updating decisive_module", 'spamhandler', 'debug');
  } elsif ($decisive eq 'spam') {
    $this->{daemon}->do_log("Updating decisive_module $module $position positive", 'spamhandler', 'debug');
    %{$this->{decisive_module}} = (
      'module' => $module,
      'position' => $position,
      'action' => 'positive'
    );
  } elsif ($decisive eq 'ham') {
    $this->{daemon}->do_log("Updating decisive_module $module $position negative", 'spamhandler', 'debug');
    %{$this->{decisive_module}} = (
      'module' => $module,
      'position' => $position,
      'action' => 'negative'
    );
  } else {
    $this->{daemon}->do_log("Found $module with unrecognized decisive value '$decisive', not updating decisive_module", 'spamhandler', 'debug');
  }
  return 1;
}

#######
## profiling timers
sub start_timer ($this, $timer) {
  $this->{'timers'}{$timer} = [gettimeofday];
  return;
}

sub end_timer ($this, $timer) {
  my $interval = tv_interval( $this->{timers}{$timer} );
  $this->{timers}{$timer} = 0;
  $this->{'timers'}{ 'd_' . $timer } = ( int( $interval * 10000 ) / 10000 );
  return;
}

sub get_timers ($this) {
  return $this->{'timers'};
}

1;
