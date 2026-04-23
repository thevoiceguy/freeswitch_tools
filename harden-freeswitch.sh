#!/usr/bin/env bash
#
# harden-freeswitch.sh
# Post-install hardening for a default FreeSWITCH on Debian/Ubuntu.
#
# What it does:
#   1. Backs up /etc/freeswitch (or source-install equivalent)
#   2. Replaces the default SIP password (vars.xml: default_password=1234)
#   3. Replaces the Event Socket password (ClueCon) and binds it to loopback
#   4. Writes generated credentials to /root/freeswitch-credentials.txt (mode 600)
#   5. Installs and configures fail2ban with a freeswitch jail
#   6. Configures ufw: default deny, allow SSH, SIP, RTP (optional source IP allowlist)
#   7. Reloads FreeSWITCH config
#   8. Writes /etc/fs_cli.conf (and ~SUDO_USER/.fs_cli_conf) so `fs_cli` keeps working
#
# What it does NOT do (leaves to you):
#   - Disable individual modules (only you know what you use)
#   - Set up SIP-TLS / SRTP (needs a domain + cert)
#   - Restrict the dialplan / configure outbound gateways
#   - Set per-extension passwords (only changes the shared default)
#
# Usage:
#   sudo ./harden-freeswitch.sh
#   sudo SIP_ALLOW_FROM="203.0.113.0/24,198.51.100.7" ./harden-freeswitch.sh
#   sudo SKIP_FIREWALL=1 ./harden-freeswitch.sh    # if you manage firewall elsewhere
#
set -euo pipefail

SIP_ALLOW_FROM="${SIP_ALLOW_FROM:-}"   # comma-separated CIDRs/IPs; empty = allow from anywhere
SKIP_FIREWALL="${SKIP_FIREWALL:-0}"
SKIP_FAIL2BAN="${SKIP_FAIL2BAN:-0}"
CREDS_FILE="/root/freeswitch-credentials.txt"

# --- preflight ---------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

# Detect FreeSWITCH config dir (package vs source install)
if [[ -d /etc/freeswitch ]]; then
  FS_CONF="/etc/freeswitch"
elif [[ -d /usr/local/freeswitch/etc/freeswitch ]]; then
  FS_CONF="/usr/local/freeswitch/etc/freeswitch"
else
  echo "Could not find FreeSWITCH config directory." >&2
  echo "Looked in /etc/freeswitch and /usr/local/freeswitch/etc/freeswitch" >&2
  exit 1
fi
echo ">>> FreeSWITCH config dir: ${FS_CONF}"

# Locate fs_cli (for reload)
if command -v fs_cli >/dev/null; then
  FS_CLI="$(command -v fs_cli)"
elif [[ -x /usr/local/freeswitch/bin/fs_cli ]]; then
  FS_CLI="/usr/local/freeswitch/bin/fs_cli"
else
  FS_CLI=""
  echo "!!! fs_cli not found in PATH; will skip live reload." >&2
fi

VARS_XML="${FS_CONF}/vars.xml"
ESL_XML="${FS_CONF}/autoload_configs/event_socket.conf.xml"

for f in "$VARS_XML" "$ESL_XML"; do
  [[ -f "$f" ]] || { echo "Missing required file: $f" >&2; exit 1; }
done

# --- 1. backup ---------------------------------------------------------------
BACKUP="/root/freeswitch-config-backup-$(date +%Y%m%d-%H%M%S).tgz"
echo ">>> Backing up ${FS_CONF} to ${BACKUP}"
tar czf "$BACKUP" -C "$(dirname "$FS_CONF")" "$(basename "$FS_CONF")"

# --- 2. generate new passwords ----------------------------------------------
gen_pw() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-28; }
NEW_SIP_PW="$(gen_pw)"
NEW_ESL_PW="$(gen_pw)"

# --- 3. patch vars.xml (default_password) ------------------------------------
echo ">>> Updating default SIP password in vars.xml"
# Match: <X-PRE-PROCESS cmd="set" data="default_password=anything"/>
# Replace the value only. Use | as sed delimiter to avoid clashing with /.
sed -i.bak -E \
  "s|(default_password=)[^\"]*|\1${NEW_SIP_PW}|g" \
  "$VARS_XML"

if ! grep -q "default_password=${NEW_SIP_PW}" "$VARS_XML"; then
  echo "!!! Failed to update default_password in vars.xml" >&2
  exit 1
fi

# --- 4. patch event_socket.conf.xml ------------------------------------------
# Capture the CURRENT ESL password before changing it, so we can authenticate
# the reload command below. Falls back to "ClueCon" (the FreeSWITCH default)
# if the file doesn't have a recognizable password line.
CURRENT_ESL_PW="$(grep -oP '<param\s+name="password"\s+value="\K[^"]+' "$ESL_XML" | head -n1 || true)"
CURRENT_ESL_PW="${CURRENT_ESL_PW:-ClueCon}"

echo ">>> Updating Event Socket password and binding to loopback"
# password
sed -i.bak -E \
  "s|(<param name=\"password\" value=\")[^\"]*(\"/>)|\1${NEW_ESL_PW}\2|" \
  "$ESL_XML"
# listen-ip -> 127.0.0.1
sed -i -E \
  "s|(<param name=\"listen-ip\" value=\")[^\"]*(\"/>)|\1127.0.0.1\2|" \
  "$ESL_XML"

if ! grep -q "value=\"${NEW_ESL_PW}\"" "$ESL_XML"; then
  echo "!!! Failed to update event socket password" >&2
  exit 1
fi

# --- 5. save credentials -----------------------------------------------------
umask 077
cat > "$CREDS_FILE" <<EOF
# FreeSWITCH credentials - generated $(date -Iseconds)
# Keep this file. Mode 600, root only.

SIP default_password (vars.xml):  ${NEW_SIP_PW}
Event Socket password (ClueCon):  ${NEW_ESL_PW}

Config backup: ${BACKUP}
Config dir:    ${FS_CONF}
EOF
chmod 600 "$CREDS_FILE"
echo ">>> Credentials written to ${CREDS_FILE}"

# --- 6. fail2ban -------------------------------------------------------------
if [[ "$SKIP_FAIL2BAN" != "1" ]]; then
  echo ">>> Installing and configuring fail2ban"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # rsyslog is pulled in because fail2ban's default sshd jail reads
  # /var/log/auth.log — minimal Debian cloud images often omit rsyslog and
  # route auth only to journald, which makes fail2ban fail to start.
  # python3-systemd lets fail2ban read directly from journald as a fallback
  # (used by the sshd.local override below).
  apt-get install -y --no-install-recommends fail2ban rsyslog python3-systemd

  # Determine FreeSWITCH log path based on the install type we detected
  # earlier (FS_CONF). Package install logs to /var/log/freeswitch,
  # source install uses prefix-relative FHS: <prefix>/var/log/freeswitch.
  if [[ "$FS_CONF" == "/etc/freeswitch" ]]; then
    FS_LOG="/var/log/freeswitch/freeswitch.log"
  else
    # FS_CONF is <prefix>/etc/freeswitch — strip two levels to get <prefix>
    FS_PREFIX="$(dirname "$(dirname "$FS_CONF")")"
    FS_LOG="${FS_PREFIX}/var/log/freeswitch/freeswitch.log"
  fi

  # fail2ban refuses to start if the logpath doesn't exist yet. If FreeSWITCH
  # hasn't created it, touch it into existence with the right ownership.
  if [[ ! -f "$FS_LOG" ]]; then
    echo ">>> $FS_LOG doesn't exist yet; creating it so fail2ban can start"
    mkdir -p "$(dirname "$FS_LOG")"
    touch "$FS_LOG"
    if id -u freeswitch >/dev/null 2>&1; then
      chown freeswitch:freeswitch "$FS_LOG" "$(dirname "$FS_LOG")" 2>/dev/null || true
    fi
  fi

  # The fail2ban package ships /etc/fail2ban/filter.d/freeswitch.conf already.
  # If missing, drop a minimal one.
  if [[ ! -f /etc/fail2ban/filter.d/freeswitch.conf ]]; then
    cat >/etc/fail2ban/filter.d/freeswitch.conf <<'EOF'
[INCLUDES]
before = common.conf

[Definition]
failregex = ^.*\[WARNING\] sofia_reg\.c:.*SIP auth (failure|challenge) \((REGISTER|INVITE)\) on sofia profile \S+ for \[.*\] from ip <HOST>$
            ^.*\[WARNING\] sofia_reg\.c:.*Can't find user \[.*@.*\] from <HOST>$
            ^.*\[WARNING\] sofia\.c:.*Hacking attempt detected from <HOST>.*$
ignoreregex =
EOF
  fi

  cat >/etc/fail2ban/jail.d/freeswitch.local <<EOF
[freeswitch]
enabled  = true
filter   = freeswitch
port     = 5060,5061,5080,5081
protocol = all
logpath  = ${FS_LOG}
maxretry = 5
findtime = 600
bantime  = 3600
EOF

  # Default sshd jail on minimal Debian reads /var/log/auth.log which doesn't
  # exist without rsyslog. We install rsyslog above, but just in case (and to
  # be robust on systems where rsyslog is delayed), also pin the sshd jail
  # to the systemd backend, which reads auth events directly from journald.
  cat >/etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
backend = systemd
EOF

  systemctl enable --now fail2ban
  systemctl restart fail2ban
fi

# --- 7. firewall (ufw) -------------------------------------------------------
if [[ "$SKIP_FIREWALL" != "1" ]]; then
  echo ">>> Configuring ufw"
  apt-get install -y --no-install-recommends ufw

  # Make sure SSH stays open BEFORE enabling, or you'll lock yourself out.
  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH

  # RTP media range (always open; calls won't work otherwise)
  ufw allow 16384:32768/udp comment 'FreeSWITCH RTP'

  if [[ -n "$SIP_ALLOW_FROM" ]]; then
    IFS=',' read -ra ALLOWS <<< "$SIP_ALLOW_FROM"
    for src in "${ALLOWS[@]}"; do
      src="$(echo "$src" | xargs)"   # trim
      [[ -z "$src" ]] && continue
      ufw allow from "$src" to any port 5060 proto udp comment 'SIP internal'
      ufw allow from "$src" to any port 5060 proto tcp comment 'SIP internal'
      ufw allow from "$src" to any port 5080 proto udp comment 'SIP external'
      ufw allow from "$src" to any port 5080 proto tcp comment 'SIP external'
      ufw allow from "$src" to any port 5061 proto tcp comment 'SIP-TLS'
    done
    echo ">>> SIP restricted to: ${SIP_ALLOW_FROM}"
  else
    ufw allow 5060/udp comment 'SIP internal'
    ufw allow 5060/tcp comment 'SIP internal'
    ufw allow 5080/udp comment 'SIP external'
    ufw allow 5080/tcp comment 'SIP external'
    ufw allow 5061/tcp comment 'SIP-TLS'
    echo "!!! SIP is open to the world. Set SIP_ALLOW_FROM to restrict by source IP."
  fi

  ufw --force enable
  ufw status verbose
fi

# --- 8. reload freeswitch ----------------------------------------------------
# IMPORTANT ORDERING: the running FreeSWITCH process still has the OLD ESL
# password in memory. We must authenticate the reload commands with the OLD
# password. Reloading mod_event_socket then re-reads the config file and
# activates the NEW password. Only AFTER that do we rewrite fs_cli.conf.
if [[ -n "$FS_CLI" ]] && systemctl is-active --quiet freeswitch; then
  echo ">>> Reloading FreeSWITCH with previous ESL password"
  "$FS_CLI" -p "$CURRENT_ESL_PW" -x 'reloadxml' || true
  # This one drops the connection mid-command (expected) and brings the
  # listener back up bound to 127.0.0.1 with the new password.
  "$FS_CLI" -p "$CURRENT_ESL_PW" -x 'reload mod_event_socket' || true
  sleep 1
fi

# --- 9. fs_cli.conf so future `fs_cli` invocations just work -----------------
# fs_cli looks at ~/.fs_cli_conf first, then /etc/fs_cli.conf. Without one of
# these, it tries the defaults (127.0.0.1:8021 / ClueCon) and fails after we
# change the password. Write a system-wide config readable only by root.
echo ">>> Writing /etc/fs_cli.conf"
cat >/etc/fs_cli.conf <<EOF
[default]
;; Auto-generated by harden-freeswitch.sh on $(date -Iseconds)
host     => 127.0.0.1
port     => 8021
password => ${NEW_ESL_PW}
debug    => 6
log-uuid => true
EOF
chmod 600 /etc/fs_cli.conf
chown root:root /etc/fs_cli.conf

# Also drop a per-user copy for the human who ran sudo, so they don't have to
# `sudo fs_cli`. Only readable by them.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  if [[ -n "$USER_HOME" && -d "$USER_HOME" ]]; then
    install -o "$SUDO_USER" -g "$SUDO_USER" -m 600 \
      /etc/fs_cli.conf "${USER_HOME}/.fs_cli_conf"
    echo ">>> Wrote ${USER_HOME}/.fs_cli_conf for ${SUDO_USER}"
  fi
fi

# Sanity check: can fs_cli connect with the new password?
if [[ -n "$FS_CLI" ]] && systemctl is-active --quiet freeswitch; then
  if "$FS_CLI" -x 'status' >/dev/null 2>&1; then
    echo ">>> fs_cli connects OK with the new password."
  else
    echo "!!! fs_cli could NOT connect after the password change." >&2
    echo "!!! Check: ${ESL_XML} and journalctl -u freeswitch -n 50" >&2
  fi
fi

# --- summary -----------------------------------------------------------------
cat <<EOF

================================================================
 FreeSWITCH hardening complete.
================================================================
 New credentials:    ${CREDS_FILE}    (mode 600, root only)
 fs_cli config:      /etc/fs_cli.conf (mode 600)
$( [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] && echo " User fs_cli:        $(getent passwd "$SUDO_USER" | cut -d: -f6)/.fs_cli_conf" )
 Config backup:      ${BACKUP}
 Original XML files: <file>.bak alongside each modified file
================================================================

Still recommended (manual):
  - Set per-extension passwords in ${FS_CONF}/directory/default/*.xml
    (don't rely on the shared default_password)
  - Restrict the dialplan; remove any outbound routes you don't need
  - Set up SIP-TLS (port 5061) with a real cert and enable SRTP
  - Subscribe to https://github.com/signalwire/freeswitch/security/advisories
  - Update any SIP clients you have with the new password:
      cat ${CREDS_FILE}

EOF
