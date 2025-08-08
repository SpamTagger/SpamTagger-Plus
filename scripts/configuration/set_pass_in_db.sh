#!/bin/bash

sed -i "s/^MYMAILCLEANERPWD.*$/MYMAILCLEANERPWD = ${@}/g" /etc/spamtagger.conf
