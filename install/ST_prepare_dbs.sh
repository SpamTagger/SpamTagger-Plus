#!/bin/bash

if [ "$SRCDIR" = "" ]; then
  SRCDIR=$(grep 'SRCDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
  if [ "SRCDIR" = "" ]; then
    SRCDIR=/var/spamtagger
  fi
fi
if [ "$VARDIR" = "" ]; then
  VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
  if [ "VARDIR" = "" ]; then
    VARDIR=/var/spamtagger
  fi
fi
if [ "$CLIENTORG" = "" ]; then
  CLIENTORG=$(grep 'CLIENTORG' /etc/spamtagger.conf | cut -d ' ' -f3)
  STHOSTNAME=$(grep 'STHOSTNAME' /etc/spamtagger.conf | cut -d ' ' -f3)
  HOSTID=$(grep 'HOSTID' /etc/spamtagger.conf | cut -d ' ' -f3)
  CLIENTID=$(grep 'CLIENTID' /etc/spamtagger.conf | cut -d ' ' -f3)
  DEFAULTDOMAIN=$(grep 'DEFAULTDOMAIN' /etc/spamtagger.conf | cut -d ' ' -f3)
  CLIENTTECHMAIL=$(grep 'CLIENTTECHMAIL' /etc/spamtagger.conf | cut -d ' ' -f3)
  MYSPAMTAGGERPWD=$(grep 'MYSPAMTAGGERPWD' /etc/spamtagger.conf | cut -d ' ' -f3)
  ISSOURCE=$(grep 'ISSOURCE' /etc/spamtagger.conf | cut -d ' ' -f3)
fi

echo "-- removing previous mariadb databases and stopping mariadb"
if [ -e /etc/systemd/system/multi-user.target.wants/mariadb.service ]; then
  systemctl stop mariadb --quiet
  systemctl disable mariadb --quiet
fi
systemctl stop mariadb@replica.socket &
systemctl stop mariadb@source.socket &
systemctl stop mariadb@replica-nopass.socket &
systemctl stop mariadb@source-nopass.socket &
sleep 3
pkill mariadb
rm -rf $VARDIR/spool/mariadb_source/*
rm -rf $VARDIR/spool/mariadb_replica/* 2>&1
rm -rf $VARDIR/log/mariadb_source/*
rm -rf $VARDIR/log/mariadb_replica/* 2>&1
rm -rf $VARDIR/run/mariadb_source/*
rm -rf $VARDIR/run/mariadb_replica/* 2>&1

# first, ask for the mariadb admin password if not known
if [ "$MYSPAMTAGGERPWD" = "" ]; then
  echo -n "enter mariadb spamtagger password: "
  read -s MYSPAMTAGGERPWD
  echo ""
fi

$SRCDIR/bin/dump_mariadb_config.pl 2>&1

# Install DBs
echo "-- generating source database"
/usr/bin/mariadb-install-db --datadir=${VARDIR}/spool/mariadb_source --defaults-file=$SRCDIR/etc/mariadb/my_source.cnf 2>/dev/null >/dev/null
chown -R mysql:mysql ${VARDIR}/spool/mariadb_source 2>&1

echo "-- generating replica database"
/usr/bin/mariadb-install-db --datadir=${VARDIR}/spool/mariadb_replica --defaults-file=$SRCDIR/etc/mariadb/my_replica.cnf 2>/dev/null >/dev/null
chown -R mysql:mysql ${VARDIR}/spool/mariadb_replica 2>&1

echo "-- starting databases in 'nopass' mode"
systemctl start mariadb@source-nopass.service
systemctl start mariadb@replica-nopass.service
sleep 3

echo "-- configuring 'root' password"
cat >/tmp/tmp_install.sql <<EOF
USE mysql;
flush privileges;
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSPAMTAGGERPWD';
EOF

/usr/bin/mariadb -S ${VARDIR}/run/mariadb_source/mariadbd.sock </tmp/tmp_install.sql 2>&1
/usr/bin/mariadb -S ${VARDIR}/run/mariadb_replica/mariadbd.sock </tmp/tmp_install.sql 2>&1

echo "-- restarting databases in 'normal' mode"
systemctl stop mariadb@replica-nopass.socket
systemctl stop mariadb@replica-nopass.service
systemctl stop mariadb@source-nopass.socket
systemctl stop mariadb@source-nopass.service
sleep 3
pkill mariadb
systemctl start mariadb@source.service
systemctl start mariadb@replica.service
sleep 3

echo "-- deleting existing dbs and users" 
cat >/tmp/tmp_install.sql <<EOF
USE mysql;
DELETE FROM user WHERE User='';
DELETE FROM db WHERE User='';
DELETE FROM user WHERE User='spamtagger';
DELETE FROM db WHERE User='spamtagger';
DROP DATABASE test;
DELETE FROM user WHERE Password='';
DROP DATABASE IF EXISTS dmarc_reporting;
DROP DATABASE IF EXISTS st_config;
DROP DATABASE IF EXISTS st_spool;
DROP DATABASE IF EXISTS st_stats;
CREATE DATABASE dmarc_reporting;
CREATE DATABASE st_config;
CREATE DATABASE st_spool;
CREATE DATABASE st_stats;
CREATE USER 'spamtagger' IDENTIFIED BY '$MYSPAMTAGGERPWD';
GRANT ALL PRIVILEGES ON st_config.* TO spamtagger@"%";
GRANT ALL PRIVILEGES ON st_spool.* TO spamtagger@"%";
GRANT ALL PRIVILEGES ON st_stats.* TO spamtagger@"%";
GRANT ALL PRIVILEGES ON dmarc_reporting.* TO spamtagger@"%";
GRANT REPLICATION SLAVE ADMIN, SLAVE MONITOR, RELOAD, BINLOG MONITOR ON *.* TO spamtagger@"%" IDENTIFIED BY '$MYSPAMTAGGERPWD';
FLUSH PRIVILEGES;
EOF

/usr/bin/mariadb -p$MYSPAMTAGGERPWD -S ${VARDIR}/run/mariadb_source/mariadbd.sock </tmp/tmp_install.sql 2>&1
/usr/bin/mariadb -p$MYSPAMTAGGERPWD -S ${VARDIR}/run/mariadb_replica/mariadbd.sock </tmp/tmp_install.sql 2>&1

rm /tmp/tmp_install.sql 2>&1

echo "-- creating spamtagger configuration tables"
$SRCDIR/bin/check_db.pl --update -s
$SRCDIR/bin/check_db.pl --update -r
$SRCDIR/bin/check_db.pl --myrepair -s
$SRCDIR/bin/check_db.pl --myrepair -r

echo "-- creating spamtagger spool tables"
for SOCKDIR in mariadb_source mariadb_replica; do
  for file in $(find $SRCDIR/install/dbs/spam -name '*.sql'); do
    /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_spool <$file
  done
  /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_spool <$SRCDIR/install/dbs/t_sp_spam.sql
done

echo "-- creating dmarc_reporting table"
/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_source/mariadbd.sock dmarc_reporting <$SRCDIR/install/dbs/dmarc_reporting.sql

echo "-- inserting system configuration wih provided values"

HOSTKEY=$(cat /etc/ssh/ssh_host_rsa_key.pub)
SOURCEHOST=127.0.0.1
SOURCEKEY=$(cat $VARDIR/.ssh/id_internal.pub)
SOURCEPASSWD=$MYSPAMTAGGERPWD

for SOCKDIR in mariadb_source mariadb_replica; do
  echo "Setting system_conf for $SOCKDIR..."
  echo "INSERT INTO system_conf (organisation, company_name, hostid, clientid, default_domain, contact_email, summary_from, analyse_to, falseneg_to, falsepos_to, src_dir, var_dir) VALUES ('$CLIENTORG', '$STHOSTNAME', '$HOSTID', NULL, '$DEFAULTDOMAIN', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$SRCDIR', '$VARDIR');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
  echo "Setting replica for $SOCKDIR..."
  echo "INSERT INTO replica (id, hostname, password, ssh_pub_key) VALUES ('$HOSTID', '127.0.0.1', '$MYSPAMTAGGERPWD', '$HOSTKEY');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
  echo "Setting source for $SOCKDIR..."
  echo "INSERT INTO source (hostname, password, ssh_pub_key) VALUES ('$SOURCEHOST', '$SOURCEPASSWD', '$SOURCEKEY');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
  echo "Setting httpd_config for $SOCKDIR..."
  echo "INSERT INTO httpd_config (serveradmin, servername) VALUES('root', 'spamtagger');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
done

echo "-- setting up replication"
echo "CHANGE MASTER TO master_host='$SOURCEHOST', master_user='spamtagger', master_password='$SOURCEPASSWD'; START SLAVE;" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_config

## creating stats tables
/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_config <$SRCDIR/install/dbs/t_st_maillog.sql

## creating temp soap authentication table
/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_spool <$SRCDIR/install/dbs/t_sp_soap_auth.sql

## creating web admin user
echo "INSERT INTO administrator (username, password, can_manage_users, can_manage_domains, can_configure, can_view_stats, can_manage_host, domains) VALUES('admin', ENCRYPT('$WEBADMINPWD'), 1, 1, 1, 1, 1, '*');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_source/mariadbd.sock st_config

echo "-- DONE -- spamtagger dbs are ready !"
