#!/bin/bash

ERRORS=0
for ext in php phtml tmpl; do
  for i in $( find /usr/spamtagger -name "*.$ext" ); do
    php -l $i | grep -v 'No syntax errors detected'
    RET=$?
    if [ $RET ]; then
      let ERRORS=$((ERRORS+1));
    fi
  done
done

exit $ERRORS
