#!/bin/bash
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
#
#   This is a custom log rotate script for SpamTagger logs
#

DAYSTOKEEP=366

SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "SRCDIR" = "" ]; then
  SRCDIR=/usr/spamtagger
fi
VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "VARDIR" = "" ]; then
  VARDIR=/var/spamtagger
fi

MYSPAMTAGGERPWD=$(grep 'MYSPAMTAGGERPWD' /etc/spamtagger.conf | cut -d ' ' -f3)

#########################
## Dumper log rotating ##
#########################
# Rotate first so that the remaining services will dump to the new log when done
if [ -s $VARDIR/log/spamtagger/dumper.log ]; then
  savelog -p -c $DAYSTOKEEP -C $VARDIR/log/spamtagger/dumper.log >/dev/null
fi

#########################
## Stop and rotate all ##
#########################

# Apache
$SRCDIR/etc/init.d/apache stop
if [ -x /usr/bin/savelog ]; then
  for i in access.log error.log ssl.log st_auth.log access_soap.log error_soap.log; do
    if [ -e $VARDIR/log/apache/$i ]; then
      savelog -p -c $DAYSTOKEEP -C $VARDIR/log/apache/$i >/dev/null
    fi
  done
fi
touch $VARDIR/log/apache/st_auth.log
chown spamtagger:spamtagger $VARDIR/log/apache/st_auth.log

# Exim Stages 1 and 2
for stage in 1 2; do
  $SRCDIR/etc/init.d/exim_stage$stage stop
  if [ -x /usr/bin/savelog ]; then
    for i in mainlog rejectlog paniclog; do
      if [ -s $VARDIR/log/exim_stage$stage/$i ]; then
        savelog -p -c $DAYSTOKEEP -C $VARDIR/log/exim_stage$stage/$i >/dev/null
      fi
    done
  fi
  if [ -x /opt/exim4/bin/exim_tidydb ]; then
    /opt/exim4/bin/exim_tidydb $VARDIR/spool/exim_stage$stage retry >/dev/null
    /opt/exim4/bin/exim_tidydb $VARDIR/spool/exim_stage$stage wait-local_smtp >/dev/null
  fi
done

# MailScanner
$SRCDIR/etc/init.d/mailscanner stop
if [ -x /usr/bin/savelog ]; then
  for i in mainlog errorlog infolog warnlog spamd.log newsld.log; do
    if [ -s $VARDIR/log/mailscanner/$i ]; then
      savelog -p -c $DAYSTOKEEP -C $VARDIR/log/mailscanner/$i >/dev/null
    fi
  done
fi
chown -R spamtagger:spamtagger $VARDIR/log/mailscanner/

# Exim Stage 4
$SRCDIR/etc/init.d/exim_stage4 stop
if [ -x /usr/bin/savelog ]; then
  for i in mainlog rejectlog paniclog; do
    if [ -s $VARDIR/log/exim_stage4/$i ]; then
      savelog -p -c $DAYSTOKEEP -C $VARDIR/log/exim_stage4/$i >/dev/null
    fi
  done
fi
if [ -x /opt/exim4/bin/exim_tidydb ]; then
  /opt/exim4/bin/exim_tidydb $VARDIR/spool/exim_stage4 retry >/dev/null
  /opt/exim4/bin/exim_tidydb $VARDIR/spool/exim_stage4 wait-local_smtp >/dev/null
fi

# clamav rotating
if [ -x /usr/bin/savelog ]; then
  for i in clamav.log freshclam.log clamd.log clamspamd.log; do
    if [ -e $VARDIR/log/clamav/$i ]; then
      savelog -u clamav -g clamav -c $DAYSTOKEEP -C $VARDIR/log/clamav/$i >/dev/null
    fi
  done
fi

# Razor
if [ -x /usr/bin/savelog ]; then
  for i in razor-agent.log; do
    if [ -s $VARDIR/.razor/$i ]; then
      savelog -p -c $DAYSTOKEEP -C $VARDIR/.razor/$i >/dev/null
    fi
  done
fi

# kaspersky rotating
if [ -x /usr/bin/savelog ]; then
  for i in kaspersky_updater.log kaspersky_stats.log; do
    if [ -e $VARDIR/log/kaspersky/$i ]; then
      savelog -p -c $DAYSTOKEEP -C $VARDIR/log/kaspersky/$i >/dev/null
    fi
  done
fi

# StatsDaemon
$SRCDIR/etc/init.d/statsdaemon stop
if [ -x /usr/bin/savelog ]; then
  savelog -p -c $DAYSTOKEEP -C $VARDIR/log/spamtagger/StatsDaemon.log >/dev/null
fi

# PrefTDaemon
$SRCDIR/etc/init.d/preftdaemon stop
if [ -x /usr/bin/savelog ]; then
  if [ -s $VARDIR/log/spamtagger/PrefTDaemon.log ]; then
    savelog -p -c $DAYSTOKEEP -C $VARDIR/log/spamtagger/PrefTDaemon.log >/dev/null
  fi
fi

# SpamHandler
$SRCDIR/etc/init.d/spamhandler stop
for i in SpamHandler.log; do
  if [ -s $VARDIR/log/spamtagger/$i ]; then
    savelog -p -c $DAYSTOKEEP -C $VARDIR/log/spamtagger/$i >/dev/null
  fi
done

# SpamTagger
if [ -x /usr/bin/savelog ]; then
  for i in update.log update2.log autolearn.log rules.log spam_sync.log st_counts-cleaner.log downloadDatas.log summaries.log updater4mc.log; do
    if [ -e $VARDIR/log/spamtagger/$i ]; then
      savelog -p -c $DAYSTOKEEP -C $VARDIR/log/spamtagger/$i >/dev/null
    fi
  done
fi

# Syslog
if [ -f /etc/init.d/sysklogd ]; then
  /etc/init.d/sysklogd restart
fi
if [ -f /etc/init.d/rsyslog ]; then
  /etc/init.d/rsyslog restart
fi

#################
## MySQL Slave ##
#################
if [ -x /usr/bin/savelog ]; then
  if [ -s $VARDIR/log/mariadb_slave/mariadb.log ]; then
    savelog -p -c $DAYSTOKEEP -C $VARDIR/log/mariadb_slave/mariadb.log >/dev/null
  fi
fi

/usr/bin/mariadb-admin -S $VARDIR/run/mariadb_slave/mariadbd.sock -uspamtagger -p$MYSPAMTAGGERPWD flush-logs
$SRCDIR/etc/init.d/mariadb_slave restart

##################
## MySQL Master ##
##################
if [ -x /usr/bin/savelog ]; then
  if [ -s $VARDIR/log/mariadb_master/mariadb.log ]; then
    savelog -p -c $DAYSTOKEEP -C $VARDIR/log/mariadb_master/mariadb.log >/dev/null
  fi
fi

/usr/bin/mariadb-admin -S $VARDIR/run/mariadb_master/mariadbd.sock -uspamtagger -p$MYSPAMTAGGERPWD flush-logs
$SRCDIR/etc/init.d/mariadb_master restart

###################
## Resync checks ##
###################
if [ -s $VARDIR/log/spamtagger/resync/resync.log ]; then
  savelog -p -c $DAYSTOKEEP -C $VARDIR/log/spamtagger/resync/resync.log >/dev/null
fi

#################
## Restart all ##
#################

$SRCDIR/etc/init.d/spamhandler start
$SRCDIR/etc/init.d/preftdaemon start
$SRCDIR/etc/init.d/statsdaemon start
$SRCDIR/etc/init.d/exim_stage4 start
$SRCDIR/etc/init.d/mailscanner start
sleep 2
$SRCDIR/etc/init.d/exim_stage2 start
$SRCDIR/etc/init.d/exim_stage1 start
$SRCDIR/etc/init.d/apache start

#############
## Cleanup ##
#############

# SpamTagger
for i in $(seq 1 10); do
  rm -rf /tmp/.spamassassin$1* >/dev/null 2>&1
done
if [ -d $VARDIR/spool/tmp ]; then
  for i in $(seq 1 10); do
    rm -rf $VARDIR/spool/tmp/.spamassassin$1* >/dev/null 2>&1
  done
fi

# MessageSniffer
if [ -d $VARDIR/log/messagesniffer ]; then
  find $VARDIR/log/messagesniffer/*[0-9].log.xml -mtime +7 -exec rm {} \;
fi

# statistics graphs
rm $VARDIR/www/stats/* >/dev/null 2>&1

################0#########
## third parties tools ##
#########################
if [ -e /opt/commtouch/etc/init.d/ctasd_initd ] && [ -f /opt/commtouch/etc/ctasd.conf ]; then
  /opt/commtouch/etc/init.d/ctasd_initd stop
  sleep 5
  /opt/commtouch/etc/init.d/ctasd_initd start
fi
if [ -e /opt/commtouch/etc/init.d/ctipd.init_d ] && [ -f /opt/commtouch/etc/ctipd.conf ]; then
  /opt/commtouch/etc/init.d/ctipd.init_d stop
  sleep 5
  /opt/commtouch/etc/init.d/ctipd.init_d start
fi

# ESET
if [ -d /var/log/eset/efs/ods ]; then
  find /var/log/eset/efs/ods -type f -mtime +7 -delete >/dev/null 2>&1
fi

# Clean old searches
find /var/spamtagger/run/spamtagger/log_search -type f -mtime +30 -delete >/dev/null 2>&1
find /var/spamtagger/run/spamtagger/stats_search -type f -mtime +30 -delete >/dev/null 2>&1
