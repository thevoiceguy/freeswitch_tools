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
#   6. Installs and configures fail2ban with a TWO-LAYER defense:
#        - 'freeswitch' jail (20 SIP auth events / 5 min -> 24h ban,
#          all-ports drop) catches the dominant modern attack pattern:
#          unauthenticated INVITE floods that never even attempt to
#          authenticate. The filter matches both 'auth failure' AND
#          'auth challenge', which by itself would false-positive on
#          legitimate users — but real softphones generate only 1-3
#          challenges per registration cycle, while scanners generate
#          20+ in seconds.
#        - 'recidive' jail (3 cross-jail bans / 24h -> 7d all-port ban)
#          escalates repeat offenders that wait out the 24h bantime.
#        - rsyslog + python3-systemd so the sshd jail works on minimal
#          Debian.
#   7. Configures ufw: default deny, allow SSH + RTP, allow SIP
#      (optionally restricted to specific source IPs)
#   8. Reloads FreeSWITCH using the PREVIOUS ESL password so the reload
#      itself authenticates; rescans sofia profiles to apply #4
#   9. Writes /etc/fs_cli.conf and ~SUDO_USER/.fs_cli_conf with the new
#      ESL password so `fs_cli` keeps working after the rotation
#  10. Runs fail2ban-regex against the live FreeSWITCH log to print a
#      one-line summary of whether the filter is actually matching.
#  11. Verifies bans are actually being enforced — places a test ban on
#      an RFC5737 documentation IP, checks that an iptables rule
#      appeared, then unbans. This catches the "fail2ban running, bans
#      logged, but no iptables rule actually present" failure mode.
#
# Lessons baked into v4:
#   - Debian 12 minimal images don't install iptables (they use nftables
#     for the kernel firewall, but no userspace iptables tool). Without
#     iptables, fail2ban's banactions silently fail and bans are theater.
#     v4 always installs iptables, even with SKIP_FIREWALL=1.
#   - fail2ban's default banaction is iptables-multiport (TCP only). For
#     SIP-on-UDP, this means the actionstart wires up TCP-only rules and
#     UDP scanner traffic walks right through. v4 sets banaction =
#     iptables-allports explicitly on the freeswitch jail.
#   - fail2ban's `reload` command does not reliably swap banactions when
#     the jail config changes. v4 always does stop -> flush iptables ->
#     start to guarantee a clean state, even on re-runs.
#   - Two overlapping freeswitch jails (strict + aggressive) cause chain
#     allocation conflicts in fail2ban's actionstart. v4 ships one jail
#     whose filter matches both attack patterns.
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

# --- preflight 1: privileges and FreeSWITCH layout ---------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

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

# --- preflight 2: runtime tools ----------------------------------------------
# Check for tools the script needs at various points, but especially the
# tools fail2ban needs to enforce bans. On Debian 12 minimal cloud images,
# iptables is NOT installed by default — the system uses nftables. fail2ban
# defaults to iptables-based banactions, so a missing iptables means bans
# will be logged but never enforced. We saw this in practice: 4.4M SIP
# auth events, fail2ban running, "Total banned: 9" in the status — and
# zero IPs actually dropped at the kernel level.
#
# We always install iptables here, even when SKIP_FIREWALL=1, because
# SKIP_FIREWALL means "don't manage firewall policy" not "don't enforce
# fail2ban bans." Those are different concerns.

echo ">>> Checking runtime dependencies"
NEEDS_INSTALL=()

# iptables: required by fail2ban banactions. Debian 12 doesn't install it
# by default. Check both PATH and /usr/sbin (which sudo includes but a
# user's PATH may not).
if ! command -v iptables >/dev/null 2>&1 && [[ ! -x /usr/sbin/iptables ]]; then
  echo ">>> iptables not found — fail2ban needs it to enforce bans"
  NEEDS_INSTALL+=(iptables)
fi

# openssl: used to generate passwords. Almost always present, but cheap
# to verify on a truly minimal install.
if ! command -v openssl >/dev/null 2>&1; then
  NEEDS_INSTALL+=(openssl)
fi

# tar: used for the config backup. Same reasoning.
if ! command -v tar >/dev/null 2>&1; then
  NEEDS_INSTALL+=(tar)
fi

if [[ ${#NEEDS_INSTALL[@]} -gt 0 ]]; then
  echo ">>> Installing missing dependencies: ${NEEDS_INSTALL[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends "${NEEDS_INSTALL[@]}"
fi

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

  # Stop fail2ban and flush iptables BEFORE writing new config. This handles
  # two cases: fresh install (no-op, fail2ban isn't running yet) and re-runs
  # (clears any stale chains and accumulated banactions from previous
  # configurations). fail2ban's `reload` does not reliably swap banactions
  # when jail configs change — full stop + flush + start is the only safe
  # path.
  systemctl stop fail2ban 2>/dev/null || true
  iptables -F 2>/dev/null || true
  iptables -X 2>/dev/null || true

  # Determine the FreeSWITCH log path based on install layout.
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

  # ---- FREESWITCH FILTER --------------------------------------------------
  # The fail2ban package ships /etc/fail2ban/filter.d/freeswitch.conf but
  # its regex doesn't match FreeSWITCH 1.10.x output (which includes a
  # CPU-usage percentage between the timestamp and [WARNING]). Overwrite
  # it directly rather than using a .local with `before =`, which causes
  # a recursive include loop that crashes fail2ban with "maximum recursion
  # depth exceeded".
  #
  # This filter matches BOTH 'SIP auth failure' AND 'SIP auth challenge'.
  # The strict version of this filter (failures only) misses the dominant
  # modern attack pattern: scanners blasting unauthenticated INVITEs, never
  # responding to the challenge, and rotating to the next source port.
  # Those probes only generate 'challenge' lines — never 'failure' — so
  # the strict filter sees nothing and bans no one despite millions of
  # log entries.
  #
  # Matching 'challenge' would false-positive on legitimate users at low
  # thresholds (every real INVITE generates a challenge), but the jail
  # threshold below (20 in 5 min) is well above what any softphone
  # produces during normal use.
  cat >/etc/fail2ban/filter.d/freeswitch.conf <<'EOF'
[Definition]
failregex = ^.*\[WARNING\]\s+sofia_reg\.c:\d+\s+SIP auth (?:failure|challenge) \((?:REGISTER|INVITE)\) on sofia profile \S+ for \[[^\]]*\] from ip <HOST>\s*$
            ^.*\[WARNING\]\s+sofia_reg\.c:\d+\s+Can't find user \[[^\]]*\] from <HOST>\s*$
ignoreregex =
EOF
  rm -f /etc/fail2ban/filter.d/freeswitch.local

  # ---- FREESWITCH JAIL ----------------------------------------------------
  # banaction = iptables-allports is critical. fail2ban's default banaction
  # is iptables-multiport, which only blocks TCP. SIP scanner traffic on
  # 5060/UDP would walk right through a TCP-only ban rule. We need the
  # all-ports, all-protocols ban to actually drop the packets.
  #
  # 20 events in 5 minutes is well below any real scanner's volume (often
  # 5+ INVITEs per second from a single IP) and well above what a
  # legitimate softphone produces (1-3 challenges per registration cycle,
  # cycles of an hour or more apart).
  cat >/etc/fail2ban/jail.d/freeswitch.local <<EOF
[freeswitch]
enabled   = true
filter    = freeswitch
port      = 5060,5061,5080,5081
protocol  = all
logpath   = ${FS_LOG}
banaction = iptables-allports
maxretry  = 20
findtime  = 300
bantime   = 86400
EOF

  # ---- RECIDIVE JAIL ------------------------------------------------------
  # Watches fail2ban's own log. If an IP gets banned 3 times within 24
  # hours (across ANY jail — sshd, freeswitch, etc.) it gets banned for a
  # week across all ports via banaction_allports.
  #
  # This catches persistent scanners that wait out the 24h bantime and
  # come back. Without recidive, the same handful of IPs cycle ban ->
  # wait -> ban -> wait indefinitely. With it, a few cycles is all they
  # get before they're locked out for a week across every port.
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
  # Default sshd jail on minimal Debian reads /var/log/auth.log which
  # doesn't exist without rsyslog. Pin it to the systemd backend, which
  # reads auth events directly from journald and works regardless of
  # rsyslog state.
  cat >/etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
backend = systemd
EOF

  systemctl enable --now fail2ban
  # Brief sleep to let actionstart wire up the chains before subsequent steps
  # try to use fail2ban-client (notably the verification step at the end).
  sleep 3
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

# --- 10. verify the fail2ban filter is matching ------------------------------
# Print a one-line summary so the operator can see whether the regex is
# catching anything in their existing log. If matched=0 here on a box with
# any meaningful log history, something is wrong — usually a log path
# mismatch or the FreeSWITCH log format has drifted from what the regex
# expects.
if [[ "$SKIP_FAIL2BAN" != "1" ]] && [[ -f "$FS_LOG" ]] && [[ -s "$FS_LOG" ]]; then
  echo
  echo ">>> fail2ban-regex result against ${FS_LOG}:"
  fail2ban-regex --print-no-missed "$FS_LOG" /etc/fail2ban/filter.d/freeswitch.conf 2>/dev/null \
    | grep -E "^Lines:|^Failregex: " \
    | head -5 || true
  echo
fi

# --- 11. verify fail2ban bans are actually being enforced --------------------
# This is the most important diagnostic in the script. It catches the
# "fail2ban looks healthy but isn't enforcing anything" failure mode
# that's invisible at the daemon level.
#
# We saw this in practice: 4.4M auth events in the FreeSWITCH log,
# fail2ban running, "Total banned: 9" in fail2ban-client status — and
# zero of those bans translated into iptables rules. Causes can include:
#   - iptables not installed (Debian 12 minimal default)
#   - banaction set to a TCP-only action while attacks come over UDP
#   - stale chains from a prior run preventing actionstart
#   - any future failure mode we haven't seen yet
#
# The check: ban an RFC5737 documentation IP, look for it in iptables,
# unban. If we see the rule, enforcement works. If not, something is
# wrong and the operator needs to know NOW, not when their box gets
# pwned.
if [[ "$SKIP_FAIL2BAN" != "1" ]]; then
  echo ">>> Verifying fail2ban ban enforcement..."
  TEST_IP="192.0.2.99"   # RFC5737, reserved for documentation, never legitimate

  fail2ban-client set freeswitch banip "$TEST_IP" >/dev/null 2>&1 || true
  sleep 2

  if iptables -L -n 2>/dev/null | grep -q "$TEST_IP"; then
    echo ">>> Confirmed: bans are enforced at the iptables level."
    fail2ban-client set freeswitch unbanip "$TEST_IP" >/dev/null 2>&1 || true
  else
    echo "!!! WARNING: fail2ban placed a ban for $TEST_IP but no iptables rule appeared."
    echo "!!! Bans are being LOGGED but NOT ENFORCED."
    echo "!!! Check:"
    echo "!!!   sudo iptables -L -n | grep f2b"
    echo "!!!   sudo tail -50 /var/log/fail2ban.log"
    echo "!!!   sudo fail2ban-client status freeswitch"
  fi
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

Active fail2ban jails (two-layer SIP defense + sshd):
  - sshd        SSH brute-force, default thresholds, journald backend
  - freeswitch  20 SIP auth events / 5 min -> 24h all-ports ban
                (catches unauthenticated INVITE floods AND credential
                brute-force in a single jail)
  - recidive    3 cross-jail bans / 24h -> 7d ALL-PORT ban
                (escalates persistent repeat offenders)

Useful checks:
  fail2ban-client status
  fail2ban-client status freeswitch
  fail2ban-client status recidive
  iptables -L INPUT -n | grep f2b      # confirm jails wired into INPUT
  iptables -L -n | grep "Chain f2b"     # all should show (1 references)
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
