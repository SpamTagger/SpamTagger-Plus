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
#           backup_config.sh

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

/usr/bin/mariadb-dump -u spamtagger -p$MYSPAMTAGGERPWD -S $VARDIR/run/mariadb_master/mariadbd.sock --ignore-table=st_config.update_patch --ignore-table=st_config.master --ignore-table=st_config.slave --master-data=2 st_config >$BACKUPFILE
