#!/bin/bash

SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi
VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$VARDIR" = "" ]; then
  VARDIR=/var/spamtagger
fi
echo "select hostname, password from source;" | $SRCDIR/bin/st_mariadb -s st_config | grep -v 'password' | tr -t '[:blank:]' ':' >/var/tmp/source.conf
MHOST=$(cat /var/tmp/source.conf | cut -d':' -f1)
MPASS=$(cat /var/tmp/source.conf | cut -d':' -f2)

if [ -s $VARDIR/spool/tmp/exim/dmarc.history ]; then

  echo -n "Importing to source database at $MHOST..."
  /opt/exim4/sbin/opendmarc-import --dbhost=$MHOST --dbport=3306 --dbname=dmarc_reporting --dbuser=spamtagger --dbpasswd=$MPASS <$VARDIR/spool/tmp/exim/dmarc.history
  /bin/rm $VARDIR/spool/tmp/exim/dmarc.history
  /bin/touch $VARDIR/spool/tmp/exim/dmarc.history
  /bin/chown spamtagger:spamtagger $VARDIR/spool/tmp/exim/dmarc.history
  echo "done."
fi

exit 0
