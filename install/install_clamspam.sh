#!/bin/bash

# TODO: Disabled for spamtagger transition. Restore when possible.
# This will likely cause the service not to start at all, so we will need to figure something out before release.
echo "ClamSpam Downloads not yet supported by SpamTagger"

VARDIR=/var/spamtagger/
SERVER="mailcleanerdl.alinto.net"

if [ -z "$(find $VARDIR/spool/clamspam -type f)" ]; then
  echo "No clamspam data found"
  if [ -d $VARDIR/spool/clamspam ]; then
    rm -rf $VARDIR/spool/clamspam
  fi
  cd $VARDIR/spool/
  curl https://$SERVER/downloads/clamspam.tar.gz --insecure -o clamspam.tar.gz 2>&1 >/dev/null
  gunzip clamspam.tar.gz
  tar -xf clamspam.tar
  rm clamspam.tar
  chown clamav:clamav -R $VARDIR/spool/clamspam
  $SRCDIR/etc/init.d/clamspamd restart
fi
