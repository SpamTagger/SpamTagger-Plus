#!/bin/bash

SRCDIR=$(grep 'SRCDIR' /etc/mailcleaner.conf | cut -d ' ' -f3)
if [ "$SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi

$SRCDIR/etc/init.d/greylistd start 2>&1 >/dev/null

echo -n "SUCCESSFULL"
