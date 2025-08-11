#!/bin/bash

sed -i "s/^MYSPAMTAGGERPWD.*$/MYSPAMTAGGERPWD = ${@}/g" /etc/spamtagger.conf
