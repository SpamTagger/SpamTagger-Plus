#!/bin/bash

if [ "$LOGFILE" = "" ]; then
  LOGFILE=/tmp/spamtagger.log
fi
if [ "$CONFFILE" = "" ]; then
  CONFFILE=/etc/spamtagger.conf
fi
if [ "$VARDIR" = "" ]; then
  VARDIR=$(grep 'VARDIR' /etc/spamtagger.conf | cut -d ' ' -f3)
  if [ "VARDIR" = "" ]; then
    VARDIR=/var/spamtagger
  fi
fi

export STVERSION="$(grep VARIANT_ID /etc/os-release | cut -d '=' -f 2)"

###############################################
### creating spamtagger group and user
if [ "$(grep 'spamtagger' /etc/passwd)" = "" ]; then
  groupadd spamtagger 2>&1 >>$LOGFILE
  useradd -d $VARDIR -s /bin/bash -g spamtagger spamtagger 2>&1 >>$LOGFILE
fi

###############################################
### check or create spool dirs
#echo ""
echo -n " - Checking/creating spool directories...              "
./ST_create_vars.sh 2>&1 >>$LOGFILE
echo "[done]"

###############################################
## generate ssh keys
if [ ! -d $VARDIR/.ssh ]; then
  mkdir $VARDIR/.ssh
fi

ssh-keygen -q -t ed25519 -f $VARDIR/.ssh/id_ed25519 -N ""
chown -R spamtagger:spamtagger $VARDIR/.ssh

if [ "$ISMASTER" = "Y" ]; then
  MASTERHOST=127.0.0.1
  MASTERKEY=$(cat $VARDIR/.ssh/id_ed25519.pub)
fi

###############################################
## stopping and desactivating standard services

for service in exim; do
  RET="$(systemctl is-active service >/dev/null)"
  if [ $RET == 0 ]; then
    systemctl disable --now $service
  fi
done

###############################################
### building libraries

# TODO: disabling this because it is trying to compile from sources which no longer exist. However,
# we still need to ensure that the remaining dependencies from within this file are installed.
echo -n " - Installing libraries...                             "
#./install_libs.sh 2>&1 >>$LOGFILE
echo "[done]"

###############################################
### building and install perl libraries

# TODO: we still need to ensure that all Perl modules are installed, but installing from sources
# within this repository is not the way to go.
echo -n " - Building libraries...                               "
#./install_perl_libs.sh 2>&1 >>$LOGFILE
echo "[done]"

###############################################
### creating databases

echo -n " - Creating databases...                               "
# TODO: `pwgen` is not packaged for CentOS. Find a different way to generate a good random password.
# Also... Move this to the user-run installer.pl script, otherwise all releases will have the same
# password suggestion.
#MYSPAMTAGGERPWD=$(pwgen -1)
#echo "MYSPAMTAGGERPWD = $MYSPAMTAGGERPWD" >>$CONFFILE
#export MYSPAMTAGGERPWD
#./ST_prepare_dbs.sh 2>&1 >>$LOGFILE

## recreate my_slave.cnf
#$SRCDIR/bin/dump_mysql_config.pl 2>&1 >> $LOGFILE
#$SRCDIR/etc/init.d/mysql_slave restart 2>&1 >>$LOGFILE
echo "[done]"
sleep 5

###############################################
### building exim

# TODO: Test CentOS's version of Exim. It likely won't have all the features we use, but if it does,
# that is incredible news!
echo -n " - Installing MTA...                                   "
#./install_exim.sh 2>&1 >>$LOGFILE

$SRCDIR/bin/dump_exim_config.pl 2>&1 >>$LOGFILE
echo "[done]"

###############################################
### building anti-spams

# TODO: Verify that we can get each of these from an upstream source. Also check if there are any
# necessary modifications that we had been making to the upstream packages (eg. additional modules
# for SpamAssassin?)
echo -n " - Building Antispam tools...                          "
# DCC has an OBS package that is already being installed
#./install_dcc.sh 2>&1 >>$LOGFILE
#./install_razor.sh 2>&1 >>$LOGFILE
#./install_pyzor.sh 2>&1 >>$LOGFILE
# SpamAssassin has a CentOS package
# ./install_sa.sh 2>&1 >>$LOGFILE
cd $SRCDIR/install 2>&1 >>$LOGFILE
echo "[done]"

###############################################
### building MailScanner

# TODO: Build from GitHub. We currently have a lightly modified fork, but hopefully we can move
# all of the modifications into a plugin or two and significantly reduce our modifications to a
# minimal patchset that can be applied to upstream at build time.
cd $SRCDIR/install
echo -n " - Installing MailScanner engine...                                "
#./install_mailscanner.sh 2>&1 >>$LOGFILE
#ln -s $SRCDIR/etc/mailscanner/spam.assassin.prefs.conf $SRCDIR/share/spamassassin/mailscanner.cf 2>&1 >/dev/null

# creating syslog entries
# with rsyslog, created in dump_exim_conf
LOGLINE=$(grep 'mailscanner/infolog' /etc/syslog.conf)
if [ "$LOGLINE" == "" ]; then
  echo "local0.info     -$VARDIR/log/mailscanner/infolog" >>/etc/syslog.conf
  echo "local0.warn     -$VARDIR/log/mailscanner/warnlog" >>/etc/syslog.conf
  echo "local0.err      $VARDIR/log/mailscanner/errorlog" >>/etc/syslog.conf
fi
RET="$(systemctl is-active rsyslog >/dev/null)"
if [ $RET == 0 ]; then
  systemctl restart rsyslog
else
  systemctl enable --now rsyslog
fi
# prevent syslog to rotate mailscanner log files
#perl -pi -e 's/`syslogd-listfiles`/`syslogd-listfiles -s mailscanner`/' /etc/cron.daily/sysklogd 2>&1 >>$LOGFILE
#perl -pi -e 's/`syslogd-listfiles --weekly`/`syslogd-listfiles --weekly -s mailscanner`/' /etc/cron.weekly/sysklogd 2>&1 >>$LOGFILE

###############################################
### install starter baysian packs
# TODO: Download these during build time so that they are relatively recent
#STPACKDIR=/root/starters
#STPACKFILE=$STPACKDIR.tar.lzma
#if [ -f $STPACKFILE ]; then
#export MYPWD=$(pwd)
#cd /root
#tar --lzma -xvf $STPACKFILE 2>&1 >>$LOGFILE
#cd $MYPWD
#fi
#if [ -d $STPACKDIR ]; then
#cp $STPACKDIR/wordlist.db $VARDIR/spool/bogofilter/database/ 2>&1 >>$LOGFILE
#chown -R spamtagger:spamtagger $VARDIR/spool/bogofilter/ 2>&1 >>$LOGFILE
#cp $STPACKDIR/bayes_toks $VARDIR/spool/spamassassin/ 2>&1 >>$LOGFILE
#chown -R spamtagger:spamtagger $VARDIR/spool/spamassassin/ 2>&1 >>$LOGFILE
#cp -a $STPACKDIR/clamspam/* $VARDIR/spool/clamspam/ 2>&1 >>$LOGFILE
#chown -R clamav:clamav $VARDIR/spool/clamspam 2>&1 >>$LOGFILE
#cp -a $STPACKDIR/clamd/* $VARDIR/spool/clamav/ 2>&1 >>$LOGFILE
#chown -R clamav:clamav $VARDIR/spool/clamav 2>&1 >>$LOGFILE
#fi
#echo "[done]"

# TODO: Move initial service dumps to `installer.pl` after the database is created
#$SRCDIR/bin/dump_clamav_config.pl 2>&1 >>$LOGFILE
#$SRCDIR/bin/dump_snmpd_config.pl 2>&1 >>$LOGFILE
#$SRCDIR/bin/dump_mailscanner_config.pl 2>&1 >>$LOGFILE
#$SRCDIR/bin/dump_apache_config.pl 2>&1 >>$LOGFILE
#$SRCDIR/bin/dump_ssh_keys.pl 2>&1 >> $LOGFILE

###############################################
### correcting some rights

chown -R spamtagger:spamtagger $SRCDIR/etc 2>&1 >/dev/null

# Move this to installer.pl also. Contents of /var/spamtagger should be empty after build
## create starter status file
cat >$VARDIR/run/spamtagger.status <<EOF
Disk : OK
Swap: 0
Raid: OK
Spools: 0
Load: 0.00
EOF
cp $VARDIR/run/spamtagger.status $VARDIR/run/spamtagger.127.0.0.1.status

# TODO: Apply default certificates directly to Apache configuration so that the temporary web server
# works in order to direct the user to the installer
## import default certificate
CERTFILE=$SRCDIR/etc/apache/certs/default.pem
KF=$(grep -n 'BEGIN RSA PRIVATE KEY' $CERTFILE | cut -d':' -f1)
KT=$(grep -n 'END RSA PRIVATE KEY' $CERTFILE | cut -d':' -f1)
CF=$(grep -n 'BEGIN CERTIFICATE' $CERTFILE | cut -d':' -f1)
CT=$(grep -n 'END CERTIFICATE' $CERTFILE | cut -d':' -f1)
KEY=$(sed -n "${KF},${KT}p;${KT}q" $CERTFILE)
CERT=$(sed -n "${CF},${CT}p;${CT}q" $CERTFILE)
# TODO: Generate unique self signed certs upon setting a hostname in installer.pl. Insert after
# database is created
#QUERY="USE st_config; UPDATE httpd_config SET tls_certificate_data='${CERT}', tls_certificate_key='${KEY}';"
#echo "$QUERY" | $SRCDIR/bin/st_mysql -m 2>&1 >>$LOGFILE
#echo "update mta_config set smtp_banner='\$smtp_active_hostname ESMTP SpamTagger Plus ($STVERSION) \$tod_full';" | $SRCDIR/bin/st_mysql -m st_config 2>&1 >>$LOGFILE

###############################################
### installing spamtagger cron job

# TODO: Load user-configurable cronjobs from '/etc/spamtagger' since these should be immutable
echo -n " - Installing scheduled jobs...                        "
echo "0,15,30,45 * * * *  $SRCDIR/scripts/cron/spamtagger_cron.pl > /dev/null" >>/var/spool/cron/crontabs/root
echo "0-59/5 * * * * $SRCDIR/bin/collect_rrd_stats.pl > /dev/null" >>/var/spool/cron/crontabs/root
crontab /var/spool/cron/crontabs/root 2>&1 >>$LOGFILE
systemctl restart cron 2>&1 >>$LOGFILE

###############################################
### starting and installing spamtagger service
# TODO: All of this will happen at the end of the install wizard
#echo -n " - Starting services...                                "
#if [ ! -d $SRCDIR/etc/firewall ]; then
#mkdir $SRCDIR/etc/firewall 2>&1 >>$LOGFILE
#fi
#$SRCDIR/bin/dump_firewall.pl 2>&1 >>$LOGFILE
#ln -s $SRCDIR/etc/init.d/spamtagger /etc/init.d/ 2>&1 >/dev/null
#/etc/init.d/spamtagger stop 2>&1 >>$LOGFILE
#update-rc.d spamtagger defaults 2>&1 >>$LOGFILE
#/etc/init.d/spamtagger start 2>&1 >>$LOGFILE
#sleep 5
#$SRCDIR/etc/init.d/apache restart 2>&1 >>$LOGFILE
#$SRCDIR/bin/collect_rrd_stats.pl 2>&1 >>$LOGFILE
#echo "[done]"
