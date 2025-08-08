#!/bin/bash

find /var/spamtagger/run/watchdog/ -type f -mmin +2 -delete
exit 0
