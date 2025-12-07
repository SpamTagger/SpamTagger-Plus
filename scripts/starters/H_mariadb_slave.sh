#!/bin/bash

DELAY=2

export PATH=$PATH:/sbin:/usr/sbin

SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi

$SRCDIR/etc/init.d/mariadb_replica stop 2>&1 >/dev/null
sleep $DELAY
PREVPROC=$(pgrep -f /etc/mariadb/my_replica.cnf)
if [ ! "$PREVPROC" = "" ]; then
  echo -n "FAILED"
  exit
else
  echo -n "SUCCESSFULL"
fi
