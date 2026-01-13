#!/bin/bash
# vim: set ts=2 sw=2 expandtab :

if [ "$LOGFILE" = "" ]; then
  LOGFILE=/tmp/spamtagger.log
fi
if [ "$CONFFILE" = "" ]; then
  CONFFILE=/etc/spamtagger.conf
fi

RELPATH=$(dirname $0)

export STVERSION="$(grep VARIANT_ID /etc/os-release | cut -d '=' -f 2)"

###############################################
### creating spamtagger group and user
if [ "$(grep 'spamtagger' /etc/passwd)" == "" ]; then
  groupadd spamtagger 2>&1 >>$LOGFILE
  useradd -d /var/spamtagger -s /bin/bash -g spamtagger spamtagger 2>&1 >>$LOGFILE
fi

###############################################
### add other users to spamtagger group
usermod -aG spamtagger Debian-exim 2>&1 >>$LOGFILE
usermod -aG spamtagger Debian-snmp 2>&1 >>$LOGFILE
# TODO: Enable the following line when mailscanner is ready
#usermod -aG spamtagger mailscanner 2>&1 >>$LOGFILE
usermod -aG spamtagger clamav 2>&1 >>$LOGFILE

###############################################
### check or create spool dirs
echo -n " - Checking/creating spool directories...              "
$RELPATH/ST_create_vars.sh 2>&1 >>$LOGFILE
echo "[done]"

###############################################
## generate ssh keys
if [ ! -d /var/spamtagger/.ssh ]; then
  mkdir /var/spamtagger/.ssh
fi

if [ ! -f /var/spamtagger/.ssh/id_internal ]; then
  ssh-keygen -t ed25519 -f /var/spamtagger/.ssh/id_internal -P ''
  chown -R spamtagger:spamtagger /var/spamtagger/.ssh
fi

if [ "$ISSOURCE" = "Y" ]; then
  SOURCEHOST=127.0.0.1
  SOURCEKEY=$(cat /var/spamtagger/.ssh/id_internal.pub)
fi

###############################################
## stopping and desactivating standard services

for service in exim; do
  RET="$(systemctl is-active service >/dev/null)"
  if [[ $RET == 0 ]]; then
    systemctl disable --now $service
  fi
done

###############################################
## initialize/enable custom services

fangfrisch -c /usr/spamtagger/etc/fangfrisch.conf initdb

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
$RELPATH/ST_prepare_dbs.sh 2>&1 >>$LOGFILE

## recreate my_replica.cnf
#/usr/spamtagger/bin/dump_mariadb_config.pl 2>&1 >> $LOGFILE
#/usr/spamtagger/etc/init.d/mariadb_replica restart 2>&1 >>$LOGFILE
echo "[done]"
sleep 5

###############################################
### building exim

# TODO: Test CentOS's version of Exim. It likely won't have all the features we use, but if it does,
# that is incredible news!
echo -n " - Installing MTA...                                   "
#./install_exim.sh 2>&1 >>$LOGFILE

$RELPATH/../bin/dump_exim_config.pl 2>&1 >>$LOGFILE
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
#cd /usr/spamtagger/install 2>&1 >>$LOGFILE
echo "[done]"

###############################################
### building MailScanner

# TODO: Build from GitHub. We currently have a lightly modified fork, but hopefully we can move
# all of the modifications into a plugin or two and significantly reduce our modifications to a
# minimal patchset that can be applied to upstream at build time.
#cd $RELPATH
echo -n " - Installing MailScanner engine...                                "
#./install_mailscanner.sh 2>&1 >>$LOGFILE
#ln -s /usr/spamtagger/etc/mailscanner/spam.assassin.prefs.conf /usr/spamtagger/share/spamassassin/mailscanner.cf 2>&1 >/dev/null

# creating syslog entries
# with rsyslog, created in dump_exim_conf
LOGLINE=$(grep 'mailscanner/infolog' /etc/syslog.conf)
if [ "$LOGLINE" == "" ]; then
  echo "local0.info     -/var/spamtagger/log/mailscanner/infolog" >>/etc/syslog.conf
  echo "local0.warn     -/var/spamtagger/log/mailscanner/warnlog" >>/etc/syslog.conf
  echo "local0.err      /var/spamtagger/log/mailscanner/errorlog" >>/etc/syslog.conf
fi
RET="$(systemctl is-active rsyslog >/dev/null)"
if [[ $RET == 0 ]]; then
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
#cp $STPACKDIR/wordlist.db /var/spamtagger/spool/bogofilter/database/ 2>&1 >>$LOGFILE
#chown -R spamtagger:spamtagger /var/spamtagger/spool/bogofilter/ 2>&1 >>$LOGFILE
#cp $STPACKDIR/bayes_toks /var/spamtagger/spool/spamassassin/ 2>&1 >>$LOGFILE
#chown -R spamtagger:spamtagger /var/spamtagger/spool/spamassassin/ 2>&1 >>$LOGFILE
#cp -a $STPACKDIR/clamspam/* /var/spamtagger/spool/clamspam/ 2>&1 >>$LOGFILE
#chown -R clamav:clamav /var/spamtagger/spool/clamspam 2>&1 >>$LOGFILE
#cp -a $STPACKDIR/clamd/* /var/spamtagger/spool/clamav/ 2>&1 >>$LOGFILE
#chown -R clamav:clamav /var/spamtagger/spool/clamav 2>&1 >>$LOGFILE
#fi
#echo "[done]"

# TODO: Move initial service dumps to `installer.pl` after the database is created
#/usr/spamtagger/bin/dump_clamav_config.pl 2>&1 >>$LOGFILE
#/usr/spamtagger/bin/dump_snmpd_config.pl 2>&1 >>$LOGFILE
#/usr/spamtagger/bin/dump_mailscanner_config.pl 2>&1 >>$LOGFILE
#/usr/spamtagger/bin/dump_apache_config.pl 2>&1 >>$LOGFILE
#/usr/spamtagger/bin/dump_ssh_keys.pl 2>&1 >> $LOGFILE

###############################################
### correcting some rights

chown -R spamtagger:spamtagger /usr/spamtagger/etc 2>&1 >/dev/null

# Move this to installer.pl also. Contents of /var/spamtagger should be empty after build
## create starter status file
cat >/var/spamtagger/run/spamtagger.status <<EOF
Disk : OK
Swap: 0
Raid: OK
Spools: 0
Load: 0.00
EOF
cp /var/spamtagger/run/spamtagger.status /var/spamtagger/run/spamtagger.127.0.0.1.status

# TODO: Apply default certificates directly to Apache configuration so that the temporary web server
# works in order to direct the user to the installer
## import default certificate
CERTFILE=/etc/spamtagger/apache/certs/default.crt
KEYFILE=/etc/spamtagger/apache/certs/default.key
if [[ -f $CERTFILE ]]; then
  KF=$(grep -n 'BEGIN RSA PRIVATE KEY' $CERTFILE | cut -d':' -f1)
  KT=$(grep -n 'END RSA PRIVATE KEY' $CERTFILE | cut -d':' -f1)
  CF=$(grep -n 'BEGIN CERTIFICATE' $CERTFILE | cut -d':' -f1)
  CT=$(grep -n 'END CERTIFICATE' $CERTFILE | cut -d':' -f1)
  KEY=$(sed -n "${KF},${KT}p;${KT}q" $CERTFILE)
  CERT=$(sed -n "${CF},${CT}p;${CT}q" $CERTFILE)
else
  
# TODO: Generate unique self signed certs upon setting a hostname in installer.pl. Insert after
# database is created
#QUERY="USE st_config; UPDATE httpd_config SET tls_certificate_data='${CERT}', tls_certificate_key='${KEY}';"
#echo "$QUERY" | /usr/spamtagger/bin/st_mariadb -m 2>&1 >>$LOGFILE
#echo "update mta_config set smtp_banner='\$smtp_active_hostname ESMTP SpamTagger Plus ($STVERSION) \$tod_full';" | /usr/spamtagger/bin/st_mariadb -m st_config 2>&1 >>$LOGFILE

###############################################
### installing spamtagger cron job

# TODO: Load user-configurable cronjobs from '/etc/spamtagger' since these should be immutable
echo -n " - Installing scheduled jobs...                        "
echo "0,15,30,45 * * * *  /usr/spamtagger/scripts/cron/spamtagger_cron.pl > /dev/null" >>/var/spool/cron/crontabs/root
echo "0-59/5 * * * * /usr/spamtagger/bin/collect_rrd_stats.pl > /dev/null" >>/var/spool/cron/crontabs/root
crontab /var/spool/cron/crontabs/root 2>&1 >>$LOGFILE
systemctl restart cron 2>&1 >>$LOGFILE

###############################################
### starting and installing spamtagger service
# TODO: All of this will happen at the end of the install wizard
#echo -n " - Starting services...                                "
#if [ ! -d /usr/spamtagger/etc/firewall ]; then
#mkdir /usr/spamtagger/etc/firewall 2>&1 >>$LOGFILE
#fi
#/usr/spamtagger/bin/dump_firewall.pl 2>&1 >>$LOGFILE
#ln -s /usr/spamtagger/etc/init.d/spamtagger /etc/init.d/ 2>&1 >/dev/null
#/etc/init.d/spamtagger stop 2>&1 >>$LOGFILE
#update-rc.d spamtagger defaults 2>&1 >>$LOGFILE
#/etc/init.d/spamtagger start 2>&1 >>$LOGFILE
#sleep 5
#/usr/spamtagger/etc/init.d/apache restart 2>&1 >>$LOGFILE
#/usr/spamtagger/bin/collect_rrd_stats.pl 2>&1 >>$LOGFILE
#echo "[done]"
openssl genrsa -out /etc/spamtagger/apache/privkey.pem


###############################################
### Apply bashrc
mkdir /var/spamtagger/state
chown spamtagger:spamtagger /var/spamtagger/state
echo 'source /usr/spamtagger/.bashrc' >> /root/.bashrc
