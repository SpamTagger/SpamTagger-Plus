#!/usr/bin/env bash
# vim: set ts=2 sw=2 expandtab :

## Define the SpamTagger repository: ${GITHOST}/${GITUSER}/${GITREPO}
# Git repo with HTTP(S) or Git protocol
#GITHOST="git@github.com:"
GITHOST="https://github.com"
# Git User
GITUSER="SpamTagger"
# Repo Name
GITREPO="SpamTagger-Plus"

# Current checksum of this script if it was called from existing repo to compare after `git pull`
if [[ "$0" == "/usr/spamtagger/debian-bootstrap/install.sh" ]]; then
  CURRENT=$(md5sum $0)
fi

# Errors which must be resolved before success, but don't justify killing the script in action
ERRORS=''

setterm --foreground blue
echo -n "# Modernizing APT Sources..."
setterm --foreground default

# Monolithic sources.list
export DEBIAN_FRONTEND=noninteractive
if [[ "$(find /etc/apt -name '*.list')" != "" ]]; then
  apt modernize-sources -y &>/dev/null
  if [ $? ]; then
    echo -e "\b\b\b x "
  else
    echo -e "\b\b\b * "
  fi
fi

setterm --foreground blue
echo -n "# Enabling Non-Free Repository..."
setterm --foreground default

if grep -q 'Components.* non-free non-free-firmware' <<<$(cat /etc/apt/sources.list.d/debian.sources 2>/dev/null); then
  echo -e "\b\b\b * "
elif [[ "$(find /etc/apt/sources.list.d/ -name '*.sources')" != "" ]]; then
  if [[ -z $CI ]]; then
    echo -ne "\rSpamTagger requires the Debian 'non-free' repository to function. Do you consent to enabling this repo? [y/N]: "
    read YN
    for i in $(find /etc/apt/sources.list.d/ -name *.sources -print); do
      if [ -z $YN ]; then
        echo -ne "\rSpamTagger requires the Debian 'non-free' repository to function. Do you consent to enabling this repo? [y/N]: "
        read YN
      fi
      if [[ "$YN" != "y" ]] && [[ "$YN" != "Y" ]]; then
        echo "Aborting..."
        exit 1
      fi
    done
  fi
  sed -i 's/Components: main.*/Components: main non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources
  echo -e "\b\b\b *"
else
  echo -e "\bx \nNo known APT sources files were found"
  exit 1
fi

setterm --foreground blue
echo -n "# Enabling Additional Repositories..."
setterm --foreground default

# Verify GPG dependency
DPKG=$(dpkg -l)
if ! grep -qP "^ii gpg" <<<$DPKG; then
  apt-get update &>/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get --assume-yes install gpg 2>/dev/null >/dev/null
fi

# SpamTagger repository
#if [ ! -e /etc/apt/keyrings/spamtagger.gpg ]; then
  #cp /usr/spamtagger/etc/spamtagger/spamtagger.asc /etc/apt/trusted.gpg.d/spamtagger.asc
  #cat /etc/apt/trusted.gpg.d/spamtagger.asc | gpg --yes --dearmor -o /etc/apt/keyrings/spamtagger.gpg
  #curl https://spamtaggerdl.alinto.net/downloads/spamtagger.gpg 2>/dev/null >/etc/apt/keyrings/spamtagger.gpg
  #cat > /etc/apt/source.list.d/spamtagger.sources <<EOF
#Types: deb
#URIs: http://cdnmcpool.spamtagger.net/
#Suites: trixie
#Components: main
#Signed-By: /etc/apt/keyrings/spamtagger.gpg
#EOF
#fi

# Docker repository
if [ ! -e /etc/apt/keyrings/docker.gpg ]; then
  curl https://download.docker.com/linux/debian/gpg 2>/dev/null >/etc/apt/trusted.gpg.d/docker.asc
  cat /etc/apt/trusted.gpg.d/docker.asc | gpg --yes --dearmor -o /etc/apt/keyrings/docker.gpg
  cat >/etc/apt/sources.list.d/docker.list <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie stable
Components: main
Signed-By: /etc/apt/keyrings/docker.gpg
EOF
fi

# DCC repository
if [ ! -e /etc/apt/keyrings/obs-home-voegelas.gpg ]; then
  curl https://download.opensuse.org/repositories/home:/voegelas/Debian_13/Release.key 2>/dev/null >/etc/apt/trusted.gpg.d/obs-home-voegelas.asc
  cat /etc/apt/trusted.gpg.d/obs-home-voegelas.asc | gpg --yes --dearmor -o /etc/apt/keyrings/obs-home-voegelas.gpg
  cat >/etc/apt/sources.list.d/obs-voegelas.list <<EOF
Types: deb
URIs: https://download.opensuse.org/repositories/home:/voegelas/Debian_13/
Suites:
Components: ./
Signed-By: /etc/apt/keyrings/obs-home-voegelas.gpg
EOF
fi

echo -e "\b\b\b * "

setterm --foreground blue
echo -n "# Refreshing APT repos..."
setterm --foreground default

rm -rf /var/lib/apt/lists/*
apt-get update &>/dev/null
if [[ $? -ne 0 ]]; then
  echo -e "\b\b\b x "
else
  echo -e "\b\b\b * "
fi

setterm --foreground blue
echo -n "# Checking/Installing APT dependencies..."
setterm --foreground default

if [[ -e /usr/spamtagger/debian-bootstrap/required.apt ]]; then
  cp /usr/spamtagger/debian-bootstrap/required.apt /tmp/required.apt
else
  curl https://raw.githubusercontent.com/SpamTagger/SpamTagger-Plus/refs/heads/main/debian-bootstrap/required.apt 2>/dev/null >/tmp/required.apt
fi

FAILED=""
for i in $(cat /tmp/required.apt); do
  if grep -qP "^ii  $i" <<<$DPKG; then
    echo -e "  Checking $i *  "
  else
    echo -ne "\r  Installing $i..."
    DEBIAN_FRONTEND=noninteractive apt-get --assume-yes install $i 2>/dev/null >/dev/null

    DPKG=$(dpkg -l)
    if grep -qP "^ii  $i" <<<$DPKG; then
      echo -e "\b\b\b * "
    else
      echo -e "\b\b\b x "
      FAILED="$FAILED
    $i"
    fi
  fi
done

if [[ $FAILED != "" ]]; then
  echo "Failed to install the following packages...
$FAILED
You can try to fix by running \`apt-get install -f\` then running this script again"
exit 1
fi

setterm --foreground blue
echo -n "# Checking SpamTagger repository..."
setterm --foreground default

# Check for existing repo
if [ -d /usr/spamtagger ]; then
  if [ ! -e /usr/spamtagger/.git/config ]; then
    echo -e "\b\b\b x \nFound '/usr/spamtagger' which is not a git repo. Please (re)move it and run the script again"
    exit 1
  fi
  if ! grep -q "${GITREPO}" <<<$(cat /usr/spamtagger/.git/config); then
    echo -e "\b\b\b x \nFound '/usr/spamtagger' which is not a ${GITREPO} repository. Please change target and run the script again"
    exit 1
  fi
# Clone instead
else
  git clone --depth 1 ${GITHOST}/${GITUSER}/${GITREPO}.git /usr/spamtagger 2>&1 >/dev/null
  if [ ! -d /usr/spamtagger ]; then
    echo -e "\b\b\b x \nFailed to clone '/usr/spamtagger' or to clone from ${GITHOST}/${GITUSER}/${GITREPO}.git"
    exit 1
  fi
fi

setterm --foreground blue
echo -n "# Updating SpamTagger repository..."
setterm --foreground default

# Update repo
cd /usr/spamtagger
git pull --rebase origin main 2>/dev/null >/dev/null
if [[ $? -ne 0 ]]; then
  echo -e "\b\b\b x Error pulling latest commits"
  exit 1
else
  echo -e "\b\b\b * "
  if [[ ! -z $CURRENT ]] && [[ $CURRENT != $(md5sum $0) ]]; then
    echo "$0 has changed. Please run the command again to ensure that you have the latest installation procedures"
    exit 1
  fi
fi

setterm --foreground blue
echo -n "# Removing unnecessary APT packages..."
setterm --foreground default

apt-get autoremove --assume-yes &>/dev/null
if [[ $? -ne 0 ]]; then
  echo -e "\b\b\b x "
  ERRORS="${ERRORS}
x Failed \`apt-get autoremove\`"
else
  echo -e "\b\b\b * "
fi

setterm --foreground blue
echo -n "# Cleaning APT archive..."
setterm --foreground default

apt-get clean --assume-yes 2>/dev/null >/dev/null
if [[ $? -ne 0 ]]; then
  echo -e "\b\b\b x "
  ERRORS="${ERRORS}
x Failed \`apt-get clean\`"
else
  echo -e "\b\b\b * "
fi

setterm --foreground blue
echo -n "# Configuring SpamTagger..."
setterm --foreground default

/usr/spamtagger/install/install.sh
if [ $! ]; then
  echo -e "\b\b\b x "
  ERRORS="${ERRORS}
x Failed running /usr/spamtagger/install/install.sh"
fi

if [[ $ERRORS != "" ]]; then
  echo "Finished with errors:"
  echo $ERRORS
  echo "Please try to remedy these errors, report them as needed, then run this script again to verify that there are no remaining errors with the installation."
fi

echo "Creating bare spamtagger configuration file..."
touch /etc/spamtagger.conf
if [ -z $SKIP_CONFIGURATION ]; then
  /usr/spamtagger/scripts/installer/installer.pl
fi
