#!/bin/bash

SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi
VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$VARDIR" = "" ]; then
  VARDIR=/var/spamtagger
fi

DOIT=$(echo "SELECT dmarc_enable_reports FROM mta_config WHERE stage=1;" | $SRCDIR/bin/st_mariadb -s st_config | grep -v 'dmarc_enable_reports')
if [ "$DOIT" != "1" ]; then
  exit 0
fi
echo "select hostname, password from source;" | $SRCDIR/bin/st_mariadb -s st_config | grep -v 'password' | tr -t '[:blank:]' ':' >/var/tmp/source.conf
MHOST=$(cat /var/tmp/source.conf | cut -d':' -f1)
MPASS=$(cat /var/tmp/source.conf | cut -d':' -f2)
ISMASTER=$(grep 'ISMASTER' /etc/spamtagger.conf | cut -d ' ' -f3)

SYSADMIN=$(echo "SELECT summary_from FROM system_conf;" | $SRCDIR/bin/st_mariadb -s st_config | grep '\@')
if [ "$SYSADMIN" != "" ]; then
  SYSADMIN=" --report-email $SYSADMIN"
fi

if [ "$ISMASTER" == "Y" ] || [ "$ISMASTER" == "y" ]; then
  echo -n "Generating DMARC reports..."
  if [ ! -d /tmp/dmarc_reports ]; then
    mkdir /tmp/dmarc_reports
  fi
  CURDIR=$(pwd)
  cd /tmp/dmarc_reports
  echo "*****************************" >>$VARDIR/log/spamtagger/dmarc_reporting.log
  /opt/exim4/sbin/opendmarc-reports --dbhost=$MHOST --dbport=3306 --dbname=dmarc_reporting --dbuser=spamtagger --dbpasswd=$MPASS --smtp-port 587 --verbose --verbose --interval=86400 $SYSADMIN 2>>$VARDIR/log/spamtagger/dmarc_reporting.log
  echo "**********" >>$VARDIR/log/spamtagger/dmarc_reporting.log
  echo "Expiring database..." >>$VARDIR/log/spamtagger/dmarc_reporting.log
  /opt/exim4/sbin/opendmarc-expire --dbhost=$MHOST --dbport=3306 --dbname=dmarc_reporting --dbuser=spamtagger --dbpasswd=$MPASS --expire=180 --verbose 2 &>>$VARDIR/log/spamtagger/dmarc_reporting.log
  echo "Done expiring." >>$VARDIR/log/spamtagger/dmarc_reporting.log
  echo "*****************************" >>$VARDIR/log/spamtagger/dmarc_reporting.log
  cd $CURDIR
  echo "done."
fi

exit 0
