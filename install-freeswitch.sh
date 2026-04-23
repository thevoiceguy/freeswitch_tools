#!/usr/bin/env bash
#
# install-freeswitch.sh
# Builds and installs FreeSWITCH from source on Debian/Ubuntu.
# Tested on Ubuntu 22.04 / 24.04 and Debian 12.
#
# Usage:  sudo ./install-freeswitch.sh [version]
# Example: sudo ./install-freeswitch.sh v1.10.12
#
set -euo pipefail

FS_VERSION="${1:-v1.10.12}"
BUILD_DIR="/usr/src"
PREFIX="/usr/local/freeswitch"
JOBS="$(nproc)"

# --- preflight ---------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

if ! grep -qiE 'debian|ubuntu' /etc/os-release; then
  echo "This script targets Debian/Ubuntu. Detected: $(. /etc/os-release; echo "$PRETTY_NAME")" >&2
  exit 1
fi

echo ">>> Installing FreeSWITCH ${FS_VERSION} into ${PREFIX}"

# --- build dependencies ------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  git build-essential cmake automake autoconf libtool libtool-bin pkg-config \
  ca-certificates wget unzip uuid-dev \
  libssl-dev zlib1g-dev libdb-dev libsqlite3-dev libcurl4-openssl-dev \
  libpcre3-dev libspeex-dev libspeexdsp-dev libldns-dev libedit-dev \
  libtiff-dev libjpeg-dev libopus-dev libsndfile1-dev libavformat-dev \
  libswscale-dev libswresample-dev libpq-dev liblua5.2-dev \
  yasm nasm

# --- build libks (SignalWire dependency) ------------------------------------
cd "${BUILD_DIR}"
if [[ ! -d libks ]]; then
  git clone https://github.com/signalwire/libks.git
fi
cd libks
git pull --ff-only || true
cmake . -DCMAKE_INSTALL_PREFIX=/usr
make -j"${JOBS}"
make install

# --- build sofia-sip ---------------------------------------------------------
cd "${BUILD_DIR}"
if [[ ! -d sofia-sip ]]; then
  git clone https://github.com/freeswitch/sofia-sip.git
fi
cd sofia-sip
git pull --ff-only || true
./bootstrap.sh
./configure --prefix=/usr
make -j"${JOBS}"
make install

# --- build spandsp -----------------------------------------------------------
# Pin to the commit BEFORE d9681c3 (June 2023), which renamed V18 mode
# constants and changed v18_init() signature. FreeSWITCH 1.10.12's mod_spandsp
# was written against the older API and won't compile against newer spandsp.
SPANDSP_PIN="d9681c3747ff4f56b1876557b9f6d894b7e6c18d~1"
cd "${BUILD_DIR}"
if [[ ! -d spandsp ]]; then
  git clone https://github.com/freeswitch/spandsp.git
fi
cd spandsp
git fetch --all --tags
git checkout "${SPANDSP_PIN}"
./bootstrap.sh
./configure --prefix=/usr
make -j"${JOBS}"
make install
ldconfig

# --- build freeswitch --------------------------------------------------------
cd "${BUILD_DIR}"
if [[ ! -d freeswitch ]]; then
  git clone https://github.com/signalwire/freeswitch.git
fi
cd freeswitch
git fetch --tags
git checkout "${FS_VERSION}"

./bootstrap.sh -j

# Disable mod_signalwire — it requires the proprietary signalwire-client-c
# library that's only available in SignalWire's token-gated repo. If you're
# building from source you almost certainly don't want this module (it just
# connects FreeSWITCH to SignalWire's cloud platform).
sed -i 's|^applications/mod_signalwire|#applications/mod_signalwire|' modules.conf

./configure --prefix="${PREFIX}" \
  --enable-core-pgsql-support \
  --disable-dependency-tracking
make -j"${JOBS}"
make install
make cd-sounds-install cd-moh-install   # default 8kHz sounds + music-on-hold

ldconfig

# --- systemd service ---------------------------------------------------------
id -u freeswitch >/dev/null 2>&1 || useradd --system --home "${PREFIX}" --shell /sbin/nologin freeswitch
chown -R freeswitch:freeswitch "${PREFIX}"

cat >/etc/systemd/system/freeswitch.service <<EOF
[Unit]
Description=FreeSWITCH Telephony Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=freeswitch
Group=freeswitch
LimitCORE=infinity
LimitNOFILE=100000
LimitNPROC=60000
LimitSTACK=250000
LimitRTPRIO=infinity
LimitRTTIME=7000000
ExecStart=${PREFIX}/bin/freeswitch -ncwait -nonat
ExecReload=${PREFIX}/bin/fs_cli -x reloadxml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now freeswitch

# --- convenience symlinks ----------------------------------------------------
ln -sf "${PREFIX}/bin/freeswitch" /usr/local/bin/freeswitch
ln -sf "${PREFIX}/bin/fs_cli"     /usr/local/bin/fs_cli

echo
echo ">>> Done. FreeSWITCH ${FS_VERSION} is installed at ${PREFIX}"
echo ">>> Service:  systemctl status freeswitch"
echo ">>> CLI:      fs_cli"
