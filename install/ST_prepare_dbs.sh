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
  ISMASTER=$(grep 'ISMASTER' /etc/spamtagger.conf | cut -d ' ' -f3)
fi
VARDIR_SANE=$(echo $VARDIR | perl -pi -e 's/\//\\\//g')

echo "-- removing previous mariadb databases and stopping mariadb"
$SRCDIR/etc/init.d/mariadb_replica stop 2>&1
$SRCDIR/etc/init.d/mariadb_source stop 2>&1
rm -rf $VARDIR/spool/mariadb_source/*
rm -rf $VARDIR/spool/mariadb_replica/* 2>&1
rm -rf $VARDIR/log/mariadb_source/*
rm -rf $VARDIR/log/mariadb_replica/* 2>&1
rm -rf $VARDIR/run/mariadb_source/*
rm -rf $VARDIR/run/mariadb_replica/* 2>&1

##
# first, ask for the mariadb admin password
if [ "$MYROOTPWD" = "" ]; then
  echo -n "enter mariadb root password: "
  read -s MYROOTPWD
  echo ""
fi

if [ "$MYSPAMTAGGERPWD" = "" ]; then
  echo -n "enter mariadb spamtagger password: "
  read -s MYSPAMTAGGERPWD
  echo ""
fi

$SRCDIR/bin/dump_mariadb_config.pl 2>&1

echo "-- generating replica database"
/usr/bin/mariadb-install-db --datadir=${VARDIR}/spool/mariadb_replica --defaults-file=$SRCDIR/etc/mariadb/my_replica.cnf 2>&1
chown -R mysql:mysql ${VARDIR}/spool/mariadb_replica 2>&1

#
# source

echo "-- generating source database"
/usr/bin/mariadb-install-db --datadir=${VARDIR}/spool/mariadb_source --defaults-file=$SRCDIR/etc/mariadb/my_source.cnf 2>&1
chown -R mysql:mysql ${VARDIR}/spool/mariadb_source 2>&1

##
# start db

cp $SRCDIR/etc/mariadb/my_replica.cnf_template $SRCDIR/etc/mariadb/my_replica.cnf
echo "-- starting mariadb"
$SRCDIR/etc/init.d/mariadb_replica start 2>&1
$SRCDIR/etc/init.d/mariadb_source start 2>&1
sleep 30

##
# delete default users and dbs and create spamtagger dbs and users

echo "-- deleting default databases and users and creating spamtagger dbs and user"
cat >/tmp/tmp_install.sql <<EOF
USE mariadb;
UPDATE user SET Password=PASSWORD('$MYROOTPWD') WHERE User='root';
DELETE FROM user WHERE User='';
DELETE FROM db WHERE User='';
DROP DATABASE test;
DELETE FROM user WHERE Password='';
DROP DATABASE IF EXISTS st_config;
DROP DATABASE IF EXISTS st_spool;
DROP DATABASE IF EXISTS st_stats;
CREATE DATABASE st_config;
CREATE DATABASE st_spool;
CREATE DATABASE st_stats;
CREATE DATABASE dmarc_reporting;
DELETE FROM user WHERE User='spamtagger';
DELETE FROM db WHERE User='spamtagger';
GRANT ALL PRIVILEGES ON st_config.* TO spamtagger@"%" IDENTIFIED BY '$MYSPAMTAGGERPWD' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON st_spool.* TO spamtagger@"%" IDENTIFIED BY '$MYSPAMTAGGERPWD' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON st_stats.* TO spamtagger@"%" IDENTIFIED BY '$MYSPAMTAGGERPWD' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON dmarc_reporting.* TO spamtagger@"%" IDENTIFIED BY '$MYSPAMTAGGERPWD' WITH GRANT OPTION;
GRANT REPLICATION SLAVE , REPLICATION CLIENT ON * . * TO  spamtagger@"%";
USE mariadb;
UPDATE user SET Reload_priv='Y' WHERE User='spamtagger';
UPDATE user SET Repl_replica_priv='Y', Repl_client_priv='Y' WHERE User='spamtagger';
FLUSH PRIVILEGES;
EOF

sleep 5

/usr/bin/mariadb -S ${VARDIR}/run/mariadb_replica/mariadbd.sock </tmp/tmp_install.sql 2>&1
/usr/bin/mariadb -S ${VARDIR}/run/mariadb_source/mariadbd.sock </tmp/tmp_install.sql 2>&1

rm /tmp/tmp_install.sql 2>&1

echo "-- creating spamtagger configuration tables"
$SRCDIR/bin/check_db.pl --update 2>&1
echo "-- creating spamtagger spool tables"

for SOCKDIR in mariadb_replica mariadb_source; do
  for file in $(ls dbs/spam/*.sql); do
    /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_spool <$file
  done
  /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_spool <dbs/t_sp_spam.sql
done

/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_source/mariadbd.sock dmarc_reporting <dbs/dmarc_reporting.sql

echo "-- inserting config and default values"

## TO DO: check these values !! either coming from the superior installation script or from /etc/spamtagger.conf

HOSTKEY=$(cat /etc/ssh/ssh_host_rsa_key.pub)
if [ "$ISMASTER" = "Y" ]; then
  MASTERHOST=127.0.0.1
  MASTERKEY=$(cat $VARDIR/.ssh/id_rsa.pub)
  MASTERPASSWD=$MYSPAMTAGGERPWD
fi

for SOCKDIR in mariadb_source; do
  echo "INSERT INTO system_conf (organisation, company_name, hostid, clientid, default_domain, contact_email, summary_from, analyse_to, falseneg_to, falsepos_to, src_dir, var_dir) VALUES ('$CLIENTORG', '$STHOSTNAME', '$HOSTID', '$CLIENTID', '$DEFAULTDOMAIN', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$CLIENTTECHMAIL', '$SRCDIR', '$VARDIR');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
  echo "INSERT INTO replica (id, hostname, password, ssh_pub_key) VALUES ('$HOSTID', '127.0.0.1', '$MYSPAMTAGGERPWD', '$HOSTKEY');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
  echo "INSERT INTO source (hostname, password, ssh_pub_key) VALUES ('$MASTERHOST', '$MASTERPASSWD', '$MASTERKEY');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
  echo "INSERT INTO httpd_config (serveradmin, servername) VALUES('root', 'spamtagger');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/$SOCKDIR/mariadbd.sock st_config
done

sleep 10
$SRCDIR/etc/init.d/mariadb_replica restart nopass
sleep 15
## MySQL redundency
echo "STOP SLAVE; CHANGE MASTER TO source_host='$MASTERHOST', source_user='spamtagger', source_password='$MASTERPASSWD'; START SLAVE;" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_config
sleep 5
$SRCDIR/etc/init.d/mariadb_replica restart
sleep 15

## creating stats tables
/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_config <dbs/t_st_maillog.sql

## creating local update table
/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_config <dbs/t_cf_update_patch.sql

## creating temp soap authentication table
/usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_spool <dbs/t_sp_soap_auth.sql

## creating web admin user
echo "INSERT INTO administrator (username, password, can_manage_users, can_manage_domains, can_configure, can_view_stats, can_manage_host, domains) VALUES('admin', ENCRYPT('$WEBADMINPWD'), 1, 1, 1, 1, 1, '*');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_source/mariadbd.sock st_config

## inserting last version update
echo "INSERT INTO update_patch VALUES('$ACTUALUPDATE', NOW(), NOW(), 'OK', 'CD release');" | /usr/bin/mariadb -uspamtagger -p$MYSPAMTAGGERPWD -S$VARDIR/run/mariadb_replica/mariadbd.sock st_config

#$SRCDIR/etc/init.d/mariadb_source stop
echo "-- DONE -- spamtagger dbs are ready !"
