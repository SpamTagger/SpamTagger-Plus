#!/bin/bash

VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "VARDIR" = "" ]; then
  VARDIR=/var/spamtagger
fi

DEFAULTUID=spamtagger
DEFAULTGID=spamtagger

#########################################################
# check if dir exists and create it if not
# params:
#   dir = directory (fullpath)
#   uid = user owner
#   gid = group owner
#
# no uid/gid check for now...

function check_dir {
  dir=$1
  if [ "$2" = "" ]; then
    uid=$DEFAULTUID
  else
    uid=$2
  fi
  if [ "$3" = "" ]; then
    gid=$DEFAULTGID
  else
    gid=$3
  fi

  if [ ! -d $dir ]; then
    echo "directory: $dir does not exists !"
    mkdir $dir
    echo "directory: $dir created"
  else
    echo "directory $dir ok"
  fi

  chown $uid:$gid $dir
}
#########################################################

################
## BEGIN SCRIPT
################

check_dir $VARDIR

####
# create generic dirs

check_dir $VARDIR/log
check_dir $VARDIR/spool
check_dir $VARDIR/run
check_dir $VARDIR/spool/tmp

####
# create exim dirs

check_dir $VARDIR/log/exim_stage1 spamtagger
check_dir $VARDIR/log/exim_stage2 spamtagger
check_dir $VARDIR/log/exim_stage4 spamtagger

check_dir $VARDIR/spool/exim_stage1
check_dir $VARDIR/spool/exim_stage1/input
check_dir $VARDIR/spool/exim_stage2
check_dir $VARDIR/spool/exim_stage2/input
check_dir $VARDIR/spool/exim_stage4
check_dir $VARDIR/spool/exim_stage4/input
check_dir $VARDIR/spool/exim_stage4/paniclog
check_dir $VARDIR/spool/exim_stage4/spamstore

####
# create mysql dirs

check_dir $VARDIR/log/mysql_master mysql spamtagger
check_dir $VARDIR/log/mysql_slave mysql spamtagger
chmod -R g+ws $VARDIR/log/mysql_master
chmod -R g+ws $VARDIR/log/mysql_slave

check_dir $VARDIR/spool/mysql_master mysql spamtagger
check_dir $VARDIR/spool/mysql_slave mysql spamtagger

check_dir $VARDIR/run/mysql_master mysql spamtagger
check_dir $VARDIR/run/mysql_slave mysql spamtagger

####
# create spamtagger dirs

check_dir $VARDIR/spool/mailscanner/
check_dir $VARDIR/spool/mailscanner/incoming
check_dir $VARDIR/spool/mailscanner/quarantine
check_dir $VARDIR/spool/mailscanner/users

check_dir $VARDIR/log/mailscanner spamtagger

check_dir $VARDIR/spam

check_dir $VARDIR/spool/spamassassin

####
# create apache dirs

check_dir $VARDIR/log/apache spamtagger
check_dir $VARDIR/www
check_dir $VARDIR/www/mrtg
check_dir $VARDIR/www/stats

####
# create spamtagger dirs

check_dir $VARDIR/spool/tmp
check_dir $VARDIR/log/spamtagger
check_dir $VARDIR/spool/spamtagger
check_dir $VARDIR/spool/spamtagger/prefs
check_dir $VARDIR/spool/spamtagger/counts
check_dir $VARDIR/spool/spamtagger/stats
check_dir $VARDIR/spool/spamtagger/scripts
check_dir $VARDIR/spool/spamtagger/addresses
check_dir $VARDIR/spool/rrdtools
check_dir $VARDIR/spool/bogofilter
check_dir $VARDIR/spool/bogofilter/database
check_dir $VARDIR/spool/bogofilter/updates
check_dir $VARDIR/spool/learningcenter
check_dir $VARDIR/spool/learningcenter/stockspam
check_dir $VARDIR/spool/learningcenter/stockham
check_dir $VARDIR/spool/learningcenter/stockrandom
check_dir $VARDIR/spool/learningcenter/stockrandom/spam
check_dir $VARDIR/spool/learningcenter/stockrandom/spam/cur
check_dir $VARDIR/spool/learningcenter/stockrandom/ham
check_dir $VARDIR/spool/learningcenter/stockrandom/ham/cur
check_dir $VARDIR/run/spamtagger
check_dir $VARDIR/run/spamtagger/log_search
check_dir $VARDIR/run/spamtagger/stats_search

####
# create clamav dirs

check_dir $VARDIR/log/clamav clamav clamav
check_dir $VARDIR/spool/clamav clamav clamav
check_dir $VARDIR/run/clamav clamav clamav
check_dir $VARDIR/spool/clamspam clamav clamav

####
# create dcc dirs

check_dir $VARDIR/spool/dcc dcc dcc
check_dir $VARDIR/run/dcc dcc dcc
