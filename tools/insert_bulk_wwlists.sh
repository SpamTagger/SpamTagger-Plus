#! /bin/bash

if [ -z "$1" ]; then
  echo ""
  echo "Please provide a file with the format"
  echo "sender recipient type"
  echo "if the recipient should be a whole domain, you need to include the '@' sign on it for example @spamtagger.org"
  echo "if the rule is for all domains please use --- as domain name"
  echo "type can be either want or block"
  exit 0
fi

FILE=$1
if [ ! -f $FILE ]; then
  echo "File $FILE not found!"
  exit 0
fi

ISMASTER=$(grep 'ISMASTER' /etc/spamtagger.conf | cut -d ' ' -f3)
if [ "$ISMASTER" = "Y" ] || [ "$ISMASTER" = "y" ]; then
  sed -i 's/^\s*//' $FILE
  sed -i 's/ /", "/g' $FILE
  sed -i 's/^/insert ignore into wwlists (sender, recipient, type, comments) values ("/' $FILE
  sed -i 's/$/", "inserting bulk rules - ST script");/g' $FILE
  sed -i 's/
//g' $FILE
  sed -i 's/"---"/""/' $FILE

  sleep 1
  st_mariadb -m st_config <$FILE
else
  echo "Please run this script on your source host"
fi
