#!/bin/bash

COUNT=0
FILES=()
for ext in php phtml tmpl; do
  for i in $( find /usr/spamtagger/www -name "*.$ext" | grep -v '/Zend' ); do
    FILES[$COUNT]=$i
    let COUNT=$((COUNT+1))
  done
done

echo 1..$COUNT

COUNT=0
for i in ${FILES[*]}; do
  let COUNT=$((COUNT+1))
  E=$(php -l $i)
  RET=$?
  if [ $RET != 0 ]; then
    echo not ok $COUNT - $i \($RET\)
    echo $E 2>/dev/null
  else
    echo ok $COUNT - $i
  fi
done
