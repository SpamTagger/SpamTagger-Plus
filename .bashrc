export PYENV_ROOT="/var/spamtagger/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
export PYENV_VERSION="3.14.2"
if command -v pyenv 1>/dev/null 2>&1; then
  eval "$(pyenv init --path)"
fi

# Execute the user-facing installer if it has never run
if [ ! -e /var/spamtagger/state/first-run-wizard ]; then
  /usr/spamtagger/state/first-run-wizard
fi

# Print system stats upon login
if [ -e /etc/spamtagger/etc/fastfetch.json ]; then
  fastfetch -c /etc/spamtagger/etc/fastfetch.json
else
  fastfetch -c /usr/spamtagger/etc/fastfetch.json
fi 
