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
#   This script will backup the configuration database
#   Usage:
#           restore_config.sh

VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "VARDIR" = "" ]; then
  VARDIR=/var/spamtagger
fi
SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "SRCDIR" = "" ]; then
  SRCDIR=/var/spamtagger
fi

MYSPAMTAGGERPWD=$(grep 'MYSPAMTAGGERPWD' /etc/spamtagger.conf | cut -d ' ' -f3)

BACKUPFILE=$1
if [ "$BACKUPFILE" = "" ]; then
  BACKUPFILE="spamtagger_config_.sql"
fi

if [ ! -f $BACKUPFILE ]; then
  echo "Backup file NOT found: $BACKUPFILE"
  exit 1
fi

/usr/bin/mariadb -u spamtagger -p$MYSPAMTAGGERPWD -S $VARDIR/run/mariadb_master/mariadbd.sock st_config <$BACKUPFILE

for p in dump_apache_config.pl dump_clamav_config.pl dump_exim_config.pl dump_firewall.pl dump_mailscanner_config.pl dump_mariadb_config.pl dump_snmpd_config.pl; do
  RES=$($SRCDIR/bin/$p 2>&1)
  if [ "$RES" != "DUMPSUCCESSFUL" ]; then
    echo "ERROR dumping: $p"
  fi
done

/etc/init.d/spamtagger stop >/dev/null 2>&1
sleep 3
killall -q -KILL exim httpd snmpd mariadbd mariadbd_safe MailScanner >/dev/null 2>&1
/etc/init.d/spamtagger start >/dev/null 2>&1
