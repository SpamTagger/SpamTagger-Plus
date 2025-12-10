#!/bin/bash
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
#
#   This script will resync the configuration database
#  usage: resync_db.sh [-F] [-C] [MHOST MPASS]
#  -F     Force resync. Ignore sync test
#  -C     Run as cron. Sends STDOUT to $LOGDIR
#  MHOST  source hostname
#  MPASS  source password

function check_status() {
  echo "Checking replica status..."

  STATUS=$(echo 'show replica status\G' | /usr/spamtagger/bin/st_mariadb -r)
  if grep -vq "Slave_SQL_Running: Yes" <<<$(echo $STATUS); then
    echo "Slave_SQL_Running failed"
    RUN=1
  elif grep -vq "Slave_IO_Running: Yes" <<<$(echo $STATUS); then
    echo "Slave_IO_Running failed"
    RUN=1
  fi
}

LOGDIR="/var/spamtagger/log/spamtagger/resync"
FAILFILE='/var/spamtagger/spool/tmp/resync_db'
LOCKFILE='/var/spamtagger/spool/tmp/resync_db.lock'
MHOST=''
MPASS=''

if [ ! -d $LOGDIR ]; then
  mkdir -p $LOGDIR
fi

for var in "$@"; do
  if [[ $var == '-F' ]]; then
    RUN=1
  elif [[ $var == '-C' ]]; then
    exec 1>>"$LOGDIR/resync.log"
    exec 2>"/dev/null"
    # If failed on previous cron run, this file will exist with a count of failures
    if [ -e $FAILFILE ]; then
      if test $(find $FAILFILE -mmin +59); then
        echo "Last try is more than 1 hours ago. Trying to fix"
        rm $FAILFILE
        RUN=1
      else
        echo "Last try is too recent. Exiting"
        exit
      fi
    fi
  # First default is source host
  elif [[ $MHOST == '' ]]; then
    MHOST=$var
  # Second default is source pass
  elif [[ $MPASS == '' ]]; then
    MPASS=$var
  # If both of the above are set, this var is excess
  else
    echo "Invalid or excess option '$var'.
usage: $0 [-F] [MHOST MPASS]
  -F     Force resync. Ignore sync test
  -C     Run as cron. Sends STDOUT to $LOGDIR
  MHOST  source hostname
  MPASS  source password"
    exit
  fi
done

if [ -e $LOCKFILE ]; then
  if test $(find $LOCKFILE -mmin +15); then
    echo "Last try is more than 15 hours ago. Removing $LOCKFILE."
    rm $LOCKFILE
  else
    echo "Lockfile ($LOCKFILE) less than 15 minutes old. Exitting..."
    exit
  fi
fi

VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "VARDIR" = "" ]; then
  VARDIR=/var/spamtagger
fi
SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "SRCDIR" = "" ]; then
  SRCDIR=/var/spamtagger
fi

echo "starting replica db..."
$SRCDIR/etc/init.d/mariadb_replica start
sleep 5

check_status
if [[ $RUN != 1 ]]; then
  echo "DBs are already in sync. Run with -F to force resync anyways."
  exit
else
  # Clear RUN as it will be used for the post-sync test result as well
  RUN=0
  echo "Running resync..."
fi

# Resync

MYSPAMTAGGERPWD=$(grep 'MYSPAMTAGGERPWD' /etc/spamtagger.conf | cut -d ' ' -f3)
echo "select hostname, password from source;" | $SRCDIR/bin/st_mariadb -r st_config | grep -v 'password' | tr -t '[:blank:]' ':' >/var/tmp/source.conf

if [ "$MHOST" != "" ]; then
  export MHOST
else
  export MHOST=$(cat /var/tmp/source.conf | cut -d':' -f1)
fi
if [ "$MPASS" != "" ]; then
  export MPASS
else
  export MPASS=$(cat /var/tmp/source.conf | cut -d':' -f2)
fi

/usr/bin/mariadb-dump -h $MHOST -uspamtagger -p$MPASS --source-data st_config >/var/tmp/source.sql
$SRCDIR/etc/init.d/mariadb_replica stop
sleep 2
rm $VARDIR/spool/mariadb_replica/source.info >/dev/null 2>&1
rm $VARDIR/spool/mariadb_replica/mariadbd-relay* >/dev/null 2>&1
rm $VARDIR/spool/mariadb_replica/relay-log.info >/dev/null 2>&1
$SRCDIR/etc/init.d/mariadb_replica start nopass
sleep 5
echo "STOP SLAVE;" | $SRCDIR/bin/st_mariadb -r
sleep 2
rm $VARDIR/spool/mariadb_replica/source.info >/dev/null 2>&1
rm $VARDIR/spool/mariadb_replica/mariadbd-relay* >/dev/null 2>&1
rm $VARDIR/spool/mariadb_replica/relay-log.info >/dev/null 2>&1

$SRCDIR/bin/st_mariadb -r st_config </var/tmp/source.sql

sleep 2
echo "CHANGE MASTER TO source_host='$MHOST', source_user='spamtagger', source_password='$MPASS'; " | $SRCDIR/bin/st_mariadb -r
# Return code should be 0 if there are no errors. Log code to RUN to catch errors that might not be presented with 'check_status'
$SRCDIR/bin/st_mariadb -r st_config </var/tmp/source.sql
RUN=$?
echo "START SLAVE;" | $SRCDIR/bin/st_mariadb -r
sleep 5

$SRCDIR/etc/init.d/mariadb_replica restart
sleep 5

# Run the check again and record results
check_status
if [[ $RUN != 1 ]]; then
  echo "Resync successful."
  # If there were previous failures, remove that flag file
  if [[ -e $FAILFILE ]]; then
    echo "Removing failfile"
    rm $FAILFILE
  fi
else
  if [[ -e $FAILFILE ]]; then
    FAILS=$(cat $FAILFILE)
    FAILS=$((FAILS + 1))
    echo $FAILS >$FAILFILE
  else
    echo 1 >$FAILFILE
  fi
fi

if [ -e $LOCKFILE ]; then
  rm $LOCKFILE
fi
