#! /bin/bash

find /var/spamtagger/spool/tmp/clamav/ -name "clamav-*.tmp" -mmin +15 -exec rm -rf {} \; >> /dev/null 2>&1
