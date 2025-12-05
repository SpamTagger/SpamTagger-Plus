#!/usr/bin/env bash

GHUSER="SpamTagger"

# Repo name, to be changed upon Stable release
GHREPO="SpamTagger-Plus"
#GHREPO="SpamTagger"

# Git/HTTP protocol, to be changed upon repo going public
#GHHOST="git@github.com:"
GHHOST="https://github.com"

# Current checksum of this script, to compare after `git pull`
CURRENT=$(md5sum $0)

# Errors which must be resolved before success, but don't justify killing the script in action
ERRORS=''

echo "Bootstrapping SpamTagger installation"

DEBIAN_FRONTEND=noninteractive apt-get --assume-yes install console-data console-setup 2>/dev/null >/dev/null
if [[ -e "/etc/default/console-setup" ]]; then
	echo -n "Configuring console..."
	sed -i 's/FONTFACE=".*/FONTFACE="Terminus"/' /etc/default/console-setup
	sed -i 's/FONTSIZE=".*/FONTSIZE="24x12"/' /etc/default/console-setup
	systemctl restart console-setup
	if [ $! ]; then
		echo -e "\b\b\b x "
	else
		echo -e "\b\b\b * "
	fi
fi

# Monolithic sources.list
if [[ "$(find /etc/apt -name '*.list')" != "" ]]; then
	echo "Modernizing APT Sources..."
	apt modernize-sources
	if [ $? ]; then
		echo -e "\b\b\b x "
	else
		echo -e "\b\b\b * "
	fi
fi

# Check for non-free
echo -n "Checking non-free repo..."

# Newer .sources files
if grep -q 'Components.* non-free non-free-firmware' <<<$(cat /etc/apt/sources.list.d/*.sources 2>/dev/null); then
	echo -e "\b\b\b * "
elif [[ "$(find /etc/apt/sources.list.d/ -name '*.sources')" != "" ]]; then
	echo -ne "\rSpamTagger requires the Debian 'non-free' repository to function. Do you consent to enabling this repo? [y/N]: "
	read YN
	for i in $(find /etc/apt/sources.list.d/ -name *.sources -print); do
		if [ -z $YN ]; then
			echo -ne "\rSpamTagger requires the Debian 'non-free' repository to function. Do you consent to enabling this repo? [y/N]: "
			read YN
		fi
		if [[ "$YN" == "y" ]] || [[ "$YN" == "Y" ]]; then
			sed -i 's/main.*/main contrib non-free non-free-firmware/' $i
			echo -e "\r Checking non-free repo * \n"
			break
		else
			echo "Aborting..."
			exit
		fi
	done
else
	echo -e "\bx \nNo known APT sources files were found"
	exit
fi

echo -n "Checking/adding extra repositories..."

# Verify GPG dependency
DPKG=$(dpkg -l)
if ! grep -qP "^ii gpg" <<<$DPKG; then
	apt-get update 2>&1 >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get --assume-yes install gpg 2>/dev/null >/dev/null
fi

# SpamTagger repository
#if [ ! -e /etc/apt/keyrings/spamtagger.gpg ]; then
	#cp /usr/spamtagger/etc/spamtagger/spamtagger.asc /etc/apt/trusted.gpg.d/spamtagger.asc
	#cat /etc/apt/trusted.gpg.d/spamtagger.asc | gpg --yes --dearmor -o /etc/apt/keyrings/spamtagger.gpg
	#wget -q -O /etc/apt/keyrings/spamtagger.gpg https://spamtaggerdl.alinto.net/downloads/spamtagger.gpg 
	#echo 'deb [signed-by=/etc/apt/keyrings/spamtagger.gpg] http://cdnmcpool.spamtagger.net trixie main' >/etc/apt/sources.list.d/spamtagger.list
#fi

# Docker repository
if [ ! -e /etc/apt/keyrings/docker.gpg ]; then
	wget -q -O /etc/apt/trusted.gpg.d/docker.asc https://download.docker.com/linux/debian/gpg
	cat /etc/apt/trusted.gpg.d/docker.asc | gpg --yes --dearmor -o /etc/apt/keyrings/docker.gpg
	echo 'deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable' >/etc/apt/sources.list.d/docker.list
fi

# DCC repository
if [ ! -e /etc/apt/keyrings/obs-home-voegelas.gpg ]; then
	wget -q -O /etc/apt/trusted.gpg.d/obs-home-voegelas.asc https://download.opensuse.org/repositories/home:/voegelas/Debian_13/Release.key
	cat /etc/apt/trusted.gpg.d/obs-home-voegelas.asc | gpg --yes --dearmor -o /etc/apt/keyrings/obs-home-voegelas.gpg
fi
if [ ! -e /etc/apt/sources.list.d/obs-voegelas.list ] && [ ! -e /etc/apt/sources.list.d/obs-voegelas.sources ]; then
	echo 'deb [signed-by=/etc/apt/keyrings/obs-home-voegelas.gpg] https://download.opensuse.org/repositories/home:/voegelas/Debian_13/ ./' | tee /etc/apt/sources.list.d/obs-voegelas.list
fi

echo -e "\b\b\b * "

# Clear cache
echo -n "Clearing APT cache..."
rm -rf /var/lib/apt/lists/*
if [[ $? -ne 0 ]]; then
	echo -e "\b\b\b x"
	exit
else
	echo -e "\b\b\b * "
fi

# Update repositories
echo -n "Updating APT repos..."
apt-get update 2>&1 >/dev/null
if [[ $? -ne 0 ]]; then
	echo -e "\b\b\b x "
else
	echo -e "\b\b\b * "
fi

FAILED=""
echo "Checking/Installing APT repos..."
for i in $(cat debian-bootstrap/required.apt); do
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
	echo "Installing APT dependencies..."
	ERRORS="${ERRORS}
x These packages failed to install:
  $FAILED
  You can try to fix by running \`apt-get install -f\` then running this script again"
fi

# Check for existing repo
echo -n "Checking SpamTagger repository..."
if [ -d /usr/spamtagger ]; then
	if [ ! -e /usr/spamtagger/.git/config ]; then
		echo -e "\b\b\b x \nFound '/usr/spamtagger' which is not a git repo. Please (re)move it and run the script again"
		exit
	fi
	if ! grep -q "${GHREPO}" <<<$(cat /usr/spamtagger/.git/config); then
		echo -e "\b\b\b x \nFound '/usr/spamtagger' which is not a ${GHREPO} repository. Please change target and run the script again"
		exit
	fi
# Clone instead
else
	git clone --depth 1 ${GHHOST}/${GHUSER}/${GHREPO}.git /usr/spamtagger 2>&1 >/dev/null
	if [ ! -d /usr/spamtagger ]; then
		echo -e "\b\b\b x \nFailed to clone '/usr/spamtagger' or to clone from https://github.com/SpamTagger/SpamTagger-Plus.git"
		exit
	fi
fi

# Update repo
cd /usr/spamtagger
git pull --rebase origin main 2>/dev/null >/dev/null
if [[ $? -ne 0 ]]; then
	echo -e "\b\b\b x Error pulling latest commits"
	#exit
else
	echo -e "\b\b\b * "
	if [[ $CURRENT != $(md5sum $0) ]]; then
		echo "$0 has changed. Please run the command again to ensure that you have the latest installation procedures"
		exit
	fi
fi

echo "Cleaning up..."

echo -n "Removing unnecessary APT packages..."
apt-get autoremove --assume-yes 2>/dev/null >/dev/null
if [[ $? -ne 0 ]]; then
	echo -e "\b\b\b x "
	ERRORS="${ERRORS}
x Failed \`apt-get autoremove\`"
else
	echo -e "\b\b\b * "
fi

echo -n "Cleaning APT archive..."
apt-get clean --assume-yes 2>/dev/null >/dev/null
if [[ $? -ne 0 ]]; then
	echo -e "\b\b\b x "
	ERRORS="${ERRORS}
x Failed \`apt-get clean\`"
else
	echo -e "\b\b\b * "
fi

clear

/usr/spamtagger/install/install.sh
if [ $! ]; then
	echo -e "\b\b\b x "
	ERRORS="${ERRORS}
x Failed running /usr/spamtagger/install/install.sh"
fi

clear
if [[ $ERRORS != "" ]]; then
	echo "Finished with errors:"
	echo $ERRORS
	echo "Please try to remedy these errors, report them as needed, then run this script again to verify that there are no remaining errors with the installation."
fi
echo "Creating bare spamtagger configuration file..."
touch /etc/spamtagger.conf
echo "Bootstrapping complete. Please run the following command for the SpamTagger Installation Wizard:"
echo "/usr/spamtagger/scripts/installer/installer.pl"
