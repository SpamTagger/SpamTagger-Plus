#!/bin/bash

DELAY=4

export PATH=$PATH:/sbin:/usr/sbin

SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi

PREVPROC=$(pgrep -f /etc/mariadb/my_source.cnf)
if [ ! "$PREVPROC" = "" ]; then
  echo -n "ALREADYRUNNING"
  exit
fi

$SRCDIR/etc/init.d/mariadb_source start 2>&1 >/dev/null
sleep $DELAY
PREVPROC=$(pgrep -f /etc/mariadb/my_source.cnf)
if [ "$PREVPROC" = "" ]; then
  echo -n "ERRORSTARTING"
  exit
else
  echo -n "SUCCESSFULL"
fi
