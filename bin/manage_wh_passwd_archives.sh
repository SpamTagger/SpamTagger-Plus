#!/bin/bash

# adds or removes domain names from the wantlist for password protected archives
# manage_wh_passwd_archives.sh add domain.tld to add it
# manage_wh_passwd_archives.sh del domain.tld to remove it

if [ $1 == "add" ]; then
  FIELD=$(echo "SELECT IFNULL(wh_passwd_archives, 'null') FROM dangerouscontent" | st_mariadb -m st_config | tail -n +2)
  if [[ "$FIELD" == "null" ]]; then
    echo "UPDATE dangerouscontent set wh_passwd_archives =  CONCAT('$2', IFNULL(wh_passwd_archives, ''));" | st_mariadb -m st_config
  else
    echo "UPDATE dangerouscontent set wh_passwd_archives =  CONCAT('$2', '\n', IFNULL(wh_passwd_archives, ''));" | st_mariadb -m st_config
  fi
  echo "$2 added"
  exit
fi

if [ $1 == "del" ]; then
  FIELD=$(echo "SELECT IFNULL(wh_passwd_archives, 'null') FROM dangerouscontent" | st_mariadb -m st_config | tail -n +2)
  if [[ "$FIELD" == "null" ]]; then
    echo "nodomain in this list"
    exit
  fi
  FIELD=$(echo "$FIELD" | sed -e "s/$2//g")
  echo "UPDATE dangerouscontent set wh_passwd_archives =  '$FIELD';" | st_mariadb -m st_config
  echo "$2 removed"
  exit
fi

echo "Usage is $0 [add|del] domain_name"
