#!/usr/bin/env bash
#
# harden-freeswitch.sh
# Post-install hardening for a default FreeSWITCH on Debian/Ubuntu.
#
# What it does:
#   1. Backs up the FreeSWITCH config dir
#   2. Replaces the default SIP password (vars.xml: default_password=1234)
#   3. Replaces the Event Socket password (ClueCon) and binds it to loopback
#   4. Enables log-auth-failures on both SIP profiles so failed registrations
#      actually reach the log (default is OFF — this is why fail2ban setups
#      for FreeSWITCH silently fail to catch anything out of the box)
#   5. Writes generated credentials to /root/freeswitch-credentials.txt
#   6. Installs and configures fail2ban with a THREE-LAYER defense:
#        - Strict 'freeswitch' jail (3 auth failures in 10 min -> 24h ban)
#          catches old-school credential brute-force attacks
#        - Loose 'freeswitch-aggressive' jail (20 events in 5 min -> 24h ban)
#          catches the modern attack pattern: unauthenticated INVITE floods
#          that never even attempt to authenticate, so they never generate
#          'SIP auth failure' lines and slip past the strict jail entirely
#        - 'recidive' jail (3 cross-jail bans in 24h -> 7d all-port ban)
#          escalates IPs that get banned repeatedly by either of the above
#        - rsyslog + python3-systemd so the sshd jail works on minimal Debian
#   7. Configures ufw: default deny, allow SSH + RTP, allow SIP
#      (optionally restricted to specific source IPs)
#   8. Reloads FreeSWITCH using the PREVIOUS ESL password so the reload itself
#      actually authenticates; rescans sofia profiles to apply #4
#   9. Writes /etc/fs_cli.conf and ~SUDO_USER/.fs_cli_conf with the new ESL
#      password so `fs_cli` keeps working after the rotation
#  10. Runs fail2ban-regex against the live FreeSWITCH log to print a
#      one-line summary of whether each filter is actually matching anything.
#      If you see "matched: 0" here, something is wrong — fix it before
#      walking away.
#
# What it does NOT do (leaves to you):
#   - Disable individual modules (too risky to guess what you use)
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
sed -i.bak -E \
  "s|(default_password=)[^\"]*|\1${NEW_SIP_PW}|g" \
  "$VARS_XML"

if ! grep -q "default_password=${NEW_SIP_PW}" "$VARS_XML"; then
  echo "!!! Failed to update default_password in vars.xml" >&2
  exit 1
fi

# --- 4. patch event_socket.conf.xml ------------------------------------------
CURRENT_ESL_PW="$(grep -oP '<param\s+name="password"\s+value="\K[^"]+' "$ESL_XML" | head -n1 || true)"
CURRENT_ESL_PW="${CURRENT_ESL_PW:-ClueCon}"

echo ">>> Updating Event Socket password and binding to loopback"
sed -i.bak -E \
  "s|(<param name=\"password\" value=\")[^\"]*(\"/>)|\1${NEW_ESL_PW}\2|" \
  "$ESL_XML"
sed -i -E \
  "s|(<param name=\"listen-ip\" value=\")[^\"]*(\"/>)|\1127.0.0.1\2|" \
  "$ESL_XML"

if ! grep -q "value=\"${NEW_ESL_PW}\"" "$ESL_XML"; then
  echo "!!! Failed to update event socket password" >&2
  exit 1
fi

# --- 4b. enable log-auth-failures on SIP profiles ----------------------------
echo ">>> Enabling log-auth-failures on SIP profiles"
for profile in "${FS_CONF}/sip_profiles/internal.xml" \
               "${FS_CONF}/sip_profiles/external.xml"; do
  [[ -f "$profile" ]] || continue
  if grep -q 'name="log-auth-failures"' "$profile"; then
    sed -i 's|<param name="log-auth-failures" value="false"/>|<param name="log-auth-failures" value="true"/>|' "$profile"
  else
    sed -i '/<\/settings>/i\    <param name="log-auth-failures" value="true"/>' "$profile"
  fi
done

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
  apt-get install -y --no-install-recommends fail2ban rsyslog python3-systemd

  if [[ "$FS_CONF" == "/etc/freeswitch" ]]; then
    FS_LOG="/var/log/freeswitch/freeswitch.log"
  else
    FS_PREFIX="$(dirname "$(dirname "$FS_CONF")")"
    FS_LOG="${FS_PREFIX}/var/log/freeswitch/freeswitch.log"
  fi

  if [[ ! -f "$FS_LOG" ]]; then
    echo ">>> $FS_LOG doesn't exist yet; creating it so fail2ban can start"
    mkdir -p "$(dirname "$FS_LOG")"
    touch "$FS_LOG"
    if id -u freeswitch >/dev/null 2>&1; then
      chown freeswitch:freeswitch "$FS_LOG" "$(dirname "$FS_LOG")" 2>/dev/null || true
    fi
  fi

  # ---- STRICT FILTER ------------------------------------------------------
  # The fail2ban package ships /etc/fail2ban/filter.d/freeswitch.conf but its
  # regex doesn't match FreeSWITCH 1.10.x output (which includes a CPU-usage
  # percentage between the timestamp and [WARNING]). Overwrite it directly
  # rather than using a .local with `before =`, which causes a recursive
  # include loop that crashes fail2ban with "maximum recursion depth exceeded".
  #
  # This filter matches `SIP auth failure` and `Can't find user` ONLY.
  # It does NOT match `SIP auth challenge` because every legitimate SIP
  # transaction begins with a server-issued challenge — banning on a single
  # challenge would ban every real user the moment they registered.
  cat >/etc/fail2ban/filter.d/freeswitch.conf <<'EOF'
[Definition]
failregex = ^.*\[WARNING\]\s+sofia_reg\.c:\d+\s+SIP auth failure \((?:REGISTER|INVITE)\) on sofia profile \S+ for \[[^\]]*\] from ip <HOST>\s*$
            ^.*\[WARNING\]\s+sofia_reg\.c:\d+\s+Can't find user \[[^\]]*\] from <HOST>\s*$
ignoreregex =
EOF
  rm -f /etc/fail2ban/filter.d/freeswitch.local

  # ---- AGGRESSIVE FILTER --------------------------------------------------
  # The strict filter above catches credential brute-force, but misses a far
  # more common attack pattern: a scanner blasting unauthenticated INVITEs
  # at the box, getting challenged, never responding, and immediately firing
  # the next probe from a different source port. That pattern generates only
  # 'SIP auth challenge' lines — never 'failure' — so the strict filter sees
  # nothing.
  #
  # This filter ALSO matches 'challenge' events. By itself that would ban
  # legitimate users on first call. Paired with maxretry=20 in the jail
  # below, it doesn't — a real softphone generates only 1-3 challenges per
  # registration cycle. A scanner generates 20 in seconds.
  cat >/etc/fail2ban/filter.d/freeswitch-aggressive.conf <<'EOF'
[Definition]
failregex = ^.*\[WARNING\]\s+sofia_reg\.c:\d+\s+SIP auth (?:failure|challenge) \((?:REGISTER|INVITE)\) on sofia profile \S+ for \[[^\]]*\] from ip <HOST>\s*$
            ^.*\[WARNING\]\s+sofia_reg\.c:\d+\s+Can't find user \[[^\]]*\] from <HOST>\s*$
ignoreregex =
EOF

  # ---- STRICT JAIL --------------------------------------------------------
  # Tighter thresholds than fail2ban defaults. Three real auth failures in
  # 10 minutes earns a 24h ban. Real users almost never trigger this; the
  # only false-positive scenario is someone fumbling a password 3+ times,
  # which is recoverable with `fail2ban-client unban <ip>`.
  cat >/etc/fail2ban/jail.d/freeswitch.local <<EOF
[freeswitch]
enabled  = true
filter   = freeswitch
port     = 5060,5061,5080,5081
protocol = all
logpath  = ${FS_LOG}
maxretry = 3
findtime = 600
bantime  = 86400
EOF

  # ---- AGGRESSIVE JAIL ----------------------------------------------------
  # Catches unauthenticated INVITE floods. 20 events in 5 minutes is well
  # below typical scanner volume (often 5+ per second from a single IP) and
  # well above what any real softphone would generate during normal use.
  #
  # If your environment has unusually chatty SIP clients (PBXs that
  # re-register aggressively, monitoring systems that probe SIP, etc.),
  # raise maxretry to 40 or 50. Watch the jail's match count for a few hours
  # after install — if your own IPs show up, the threshold is too low.
  cat >/etc/fail2ban/jail.d/freeswitch-aggressive.local <<EOF
[freeswitch-aggressive]
enabled  = true
filter   = freeswitch-aggressive
port     = 5060,5061,5080,5081
protocol = all
logpath  = ${FS_LOG}
maxretry = 20
findtime = 300
bantime  = 86400
EOF

  # ---- RECIDIVE JAIL ------------------------------------------------------
  # The recidive jail watches fail2ban's own log. If an IP gets banned 3
  # times within 24 hours (across ANY jail — sshd, freeswitch, the
  # aggressive jail, etc.) it gets banned for a week across all ports
  # via banaction_allports.
  #
  # This catches the persistent scanners that wait out a 24h bantime and
  # immediately come back. Without recidive, the same handful of IPs cycle
  # ban -> wait -> ban -> wait indefinitely. With it, a few cycles is all
  # they get before they're locked out for a week across every port.
  #
  # No false-positive risk: recidive only escalates IPs that fail2ban has
  # ALREADY banned multiple times.
  cat >/etc/fail2ban/jail.d/recidive.local <<EOF
[recidive]
enabled   = true
logpath   = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime   = 604800
findtime  = 86400
maxretry  = 3
EOF

  # ---- SSHD ---------------------------------------------------------------
  # Default sshd jail on minimal Debian reads /var/log/auth.log which doesn't
  # exist without rsyslog. Pin it to the systemd backend, which reads auth
  # events directly from journald and works regardless of rsyslog state.
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

  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH

  ufw allow 16384:32768/udp comment 'FreeSWITCH RTP'

  if [[ -n "$SIP_ALLOW_FROM" ]]; then
    IFS=',' read -ra ALLOWS <<< "$SIP_ALLOW_FROM"
    for src in "${ALLOWS[@]}"; do
      src="$(echo "$src" | xargs)"
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
if [[ -n "$FS_CLI" ]] && systemctl is-active --quiet freeswitch; then
  echo ">>> Reloading FreeSWITCH with previous ESL password"
  "$FS_CLI" -p "$CURRENT_ESL_PW" -x 'reloadxml' || true
  "$FS_CLI" -p "$CURRENT_ESL_PW" -x 'sofia profile internal rescan' || true
  "$FS_CLI" -p "$CURRENT_ESL_PW" -x 'sofia profile external rescan' || true
  "$FS_CLI" -p "$CURRENT_ESL_PW" -x 'reload mod_event_socket' || true
  sleep 1
fi

# --- 9. fs_cli.conf ----------------------------------------------------------
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

if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  if [[ -n "$USER_HOME" && -d "$USER_HOME" ]]; then
    install -o "$SUDO_USER" -g "$SUDO_USER" -m 600 \
      /etc/fs_cli.conf "${USER_HOME}/.fs_cli_conf"
    echo ">>> Wrote ${USER_HOME}/.fs_cli_conf for ${SUDO_USER}"
  fi
fi

if [[ -n "$FS_CLI" ]] && systemctl is-active --quiet freeswitch; then
  if "$FS_CLI" -x 'status' >/dev/null 2>&1; then
    echo ">>> fs_cli connects OK with the new password."
  else
    echo "!!! fs_cli could NOT connect after the password change." >&2
    echo "!!! Check: ${ESL_XML} and journalctl -u freeswitch -n 50" >&2
  fi
fi

# --- 10. verify the fail2ban filters are matching ----------------------------
# Print a one-line summary per filter so the operator can see whether each
# regex is catching anything in their existing log. If matched=0 here on a
# box with any meaningful log history, something is wrong — usually a log
# path mismatch or the FreeSWITCH log format has drifted from what the
# regex expects.
if [[ "$SKIP_FAIL2BAN" != "1" ]] && [[ -f "$FS_LOG" ]] && [[ -s "$FS_LOG" ]]; then
  echo
  echo ">>> fail2ban-regex: strict filter against ${FS_LOG}:"
  fail2ban-regex --print-no-missed "$FS_LOG" /etc/fail2ban/filter.d/freeswitch.conf 2>/dev/null \
    | grep -E "^Lines:|^Failregex: " \
    | head -5 || true
  echo
  echo ">>> fail2ban-regex: aggressive filter against ${FS_LOG}:"
  fail2ban-regex --print-no-missed "$FS_LOG" /etc/fail2ban/filter.d/freeswitch-aggressive.conf 2>/dev/null \
    | grep -E "^Lines:|^Failregex: " \
    | head -5 || true
  echo
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

Active fail2ban jails (three-layer SIP defense):
  - sshd                   SSH brute-force, default thresholds
  - freeswitch             3 auth failures / 10 min -> 24h ban
                           (catches credential brute-force)
  - freeswitch-aggressive  20 auth events / 5 min -> 24h ban
                           (catches unauthenticated INVITE floods —
                           the dominant modern attack pattern)
  - recidive               3 cross-jail bans / 24h -> 7d ALL-PORT ban
                           (escalates persistent repeat offenders)

Useful checks:
  fail2ban-client status
  fail2ban-client status freeswitch
  fail2ban-client status freeswitch-aggressive
  fail2ban-client status recidive
  cat ${CREDS_FILE}

Still recommended (manual):
  - Set per-extension passwords in ${FS_CONF}/directory/default/*.xml
    (don't rely on the shared default_password)
  - Restrict the dialplan; remove any outbound routes you don't need
  - Set up SIP-TLS (port 5061) with a real cert and enable SRTP
  - Subscribe to https://github.com/signalwire/freeswitch/security/advisories
  - Update any SIP clients you have with the new password:
      cat ${CREDS_FILE}

EOF
