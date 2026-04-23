#!/usr/bin/env bash
#
# install-freeswitch-token.sh
# Installs FreeSWITCH on Debian using SignalWire's prebuilt packages.
# Requires a free SignalWire Personal Access Token (PAT):
#   1. Sign up at https://signalwire.com
#   2. In your SignalWire Space, open "Personal Access Tokens"
#   3. Create a token (the FreeSWITCH scope is enabled by default)
#
# Usage:
#   sudo TOKEN=pt_xxxxxxxxxxxx ./install-freeswitch-token.sh
#   sudo ./install-freeswitch-token.sh pt_xxxxxxxxxxxx
#   # Optional: override the Debian codename (bookworm, bullseye, ...)
#   sudo CODENAME=bookworm TOKEN=pt_xxx ./install-freeswitch-token.sh
#
set -euo pipefail

TOKEN="${TOKEN:-${1:-}}"
CODENAME="${CODENAME:-}"
REPO_HOST="freeswitch.signalwire.com"
REPO_PATH="repo/deb/debian-release"
KEYRING="/usr/share/keyrings/signalwire-freeswitch-repo.gpg"
SOURCES_LIST="/etc/apt/sources.list.d/freeswitch.list"
AUTH_FILE="/etc/apt/auth.conf.d/signalwire.conf"

# --- preflight ---------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

if [[ -z "$TOKEN" ]]; then
  echo "Error: SignalWire Personal Access Token not provided." >&2
  echo "Pass it via TOKEN env var or as the first argument." >&2
  exit 1
fi

if ! grep -qiE 'debian|ubuntu' /etc/os-release; then
  echo "This script targets Debian (and Ubuntu, best-effort)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends gnupg2 wget lsb-release ca-certificates

# Determine codename. SignalWire's repo officially serves Debian codenames
# (bullseye, bookworm, ...). On Ubuntu, override with CODENAME=bookworm.
if [[ -z "$CODENAME" ]]; then
  CODENAME="$(lsb_release -sc)"
fi
echo ">>> Using repo codename: ${CODENAME}"

# --- 1. fetch the repo signing key (auth'd with the PAT) ---------------------
echo ">>> Downloading SignalWire repo key"
wget --quiet \
  --http-user=signalwire --http-password="$TOKEN" \
  -O "$KEYRING" \
  "https://${REPO_HOST}/${REPO_PATH}/signalwire-freeswitch-repo.gpg"
chmod 644 "$KEYRING"

# --- 2. tell apt how to auth to the repo -------------------------------------
echo ">>> Writing apt auth file"
mkdir -p "$(dirname "$AUTH_FILE")"
cat > "$AUTH_FILE" <<EOF
machine ${REPO_HOST}
login signalwire
password ${TOKEN}
EOF
chmod 600 "$AUTH_FILE"

# --- 3. add the repo ---------------------------------------------------------
echo ">>> Adding apt source"
cat > "$SOURCES_LIST" <<EOF
deb     [signed-by=${KEYRING}] https://${REPO_HOST}/${REPO_PATH}/ ${CODENAME} main
deb-src [signed-by=${KEYRING}] https://${REPO_HOST}/${REPO_PATH}/ ${CODENAME} main
EOF

# --- 4. install --------------------------------------------------------------
echo ">>> Installing freeswitch-meta-all (this is the big one)"
apt-get update
apt-get install -y freeswitch-meta-all

# --- 5. enable the service ---------------------------------------------------
# The packages ship a systemd unit; just enable + start it.
systemctl enable --now freeswitch || {
  echo "!!! Service didn't start cleanly. Check: journalctl -u freeswitch -e" >&2
}

echo
echo ">>> Done."
echo ">>> Status: systemctl status freeswitch"
echo ">>> CLI:    fs_cli"
echo ">>> Config: /etc/freeswitch"
