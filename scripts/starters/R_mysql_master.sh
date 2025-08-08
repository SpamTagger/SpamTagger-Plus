#!/bin/bash

export PATH=$PATH:/sbin:/usr/sbin

SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi

$SRCDIR/etc/init.d/mysql_master restart 2>&1 >/dev/null
if test $? -ne 0; then
  echo -n "FAILED"
  exit 1
fi
echo -n "SUCCESSFULL"
exit 0
