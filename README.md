# FreeSWITCH on Debian — install & harden

A small set of bash scripts to get FreeSWITCH running on a fresh Debian box and lock it down before it touches the public internet.

## What's in here

| Script | Purpose |
| --- | --- |
| `install-freeswitch.sh` | Build and install FreeSWITCH from source. Works without a SignalWire account. |
| `install-freeswitch-token.sh` | Install FreeSWITCH from SignalWire's prebuilt Debian packages. Faster, but requires a free SignalWire Personal Access Token. |
| `harden-freeswitch.sh` | Post-install hardening: rotates default passwords, sets up `fail2ban`, configures `ufw`, fixes `fs_cli`. Run this once after either installer. |

Pick **one** installer, then run the hardening script.

## Requirements

- Debian 12 (Bookworm) — fully supported by both installers
- Debian 13 (Trixie) — not tested; only `install-freeswitch.sh` (from source); SignalWire's package repo for trixie is not yet populated
- Ubuntu 22.04 / 24.04 — not tested ; `install-freeswitch.sh` works; the token installer is best-effort (set `CODENAME=bookworm`)
- Root access (run with `sudo`)
- A clean box. None of these scripts are designed to coexist with an existing FreeSWITCH install.

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPO.git
cd YOUR-REPO
chmod +x *.sh

# 1. Install (pick ONE)
sudo ./install-freeswitch.sh                                    # source build, ~20 min
# OR
sudo TOKEN=pat_yourSignalWireToken ./install-freeswitch-token.sh  # packages, ~2 min

# 2. Harden — restrict SIP to your known source IPs if you can
sudo SIP_ALLOW_FROM="203.0.113.0/24,198.51.100.7" ./harden-freeswitch.sh

# 3. Read your generated credentials
sudo cat /root/freeswitch-credentials.txt
```

---

## `install-freeswitch.sh` — build from source

Builds FreeSWITCH and its main dependencies (`libks`, `sofia-sip`, `spandsp`) from upstream git, installs everything to `/usr/local/freeswitch`, creates a `freeswitch` system user, and registers a systemd unit.

### Usage

```bash
sudo ./install-freeswitch.sh             # installs v1.10.12 (default)
sudo ./install-freeswitch.sh v1.10.11    # pin to a specific tag
```

### What it does

1. Installs build dependencies via `apt`
2. Clones and builds `libks`, `sofia-sip`, `spandsp` into `/usr/src/`
3. Clones `signalwire/freeswitch`, checks out the requested tag, builds with `make -j$(nproc)`
4. Installs core sounds (8 kHz) and music-on-hold
5. Creates the `freeswitch` system user, sets ownership on `/usr/local/freeswitch`
6. Writes a systemd unit at `/etc/systemd/system/freeswitch.service` with appropriate `RTPRIO`/`NOFILE` limits
7. Enables and starts the service, symlinks `freeswitch` and `fs_cli` into `/usr/local/bin`

### Notes

- Build takes 15–30 minutes depending on the box.
- Works on Debian 12, Debian 13, and recent Ubuntu LTS.
- Source build is required for Debian 13 today (SignalWire's trixie repo is incomplete).

---

## `install-freeswitch-token.sh` — SignalWire packages

Installs the prebuilt `freeswitch-meta-all` Debian package from SignalWire's authenticated repository. Fast and uses systemd integration that's already maintained for you.

### Requirements

A free SignalWire Personal Access Token (PAT):

1. Sign up at <https://signalwire.com>
2. Open your SignalWire Space → **Personal Access Tokens**
3. Create a token (the FreeSWITCH scope is enabled by default)
4. Copy the token somewhere safe — you can't see it again after closing the dialog

### Usage

```bash
sudo TOKEN=pat_yourtokenhere ./install-freeswitch-token.sh
# or
sudo ./install-freeswitch-token.sh pat_yourtokenhere

# Override the codename (e.g. for Ubuntu, point at the closest Debian release)
sudo CODENAME=bookworm TOKEN=pat_xxx ./install-freeswitch-token.sh
```

### What it does

1. Installs `gnupg2`, `wget`, `lsb-release`, `ca-certificates`
2. Downloads the SignalWire repo signing key (authenticated with your PAT) to `/usr/share/keyrings/signalwire-freeswitch-repo.gpg`
3. Writes apt credentials to `/etc/apt/auth.conf.d/signalwire.conf` (mode 600)
4. Adds the repo to `/etc/apt/sources.list.d/freeswitch.list` for your codename
5. Installs `freeswitch-meta-all` (the kitchen-sink meta-package — every module, sounds, MOH)
6. Enables and starts the `freeswitch` systemd service

### Notes

- The token in `/etc/apt/auth.conf.d/signalwire.conf` is needed for future `apt update` and package upgrades. Don't delete it.
- For a leaner install, swap `freeswitch-meta-all` in the script for `freeswitch-meta-vanilla` plus only the `freeswitch-mod-*` packages you actually need.
- **Debian 13 (Trixie):** SignalWire's trixie repo currently ships almost nothing. Use the source-build script instead, or use Debian 12.
- **Ubuntu:** not officially supported, but usually works with `CODENAME=bookworm`. For production on Ubuntu, prefer the source build.

---

## `harden-freeswitch.sh` — post-install hardening

Run this **once** after either installer, before exposing the box to the internet. The defaults that ship with FreeSWITCH (passwords `1234` and `ClueCon`) get exploited within hours of going online.

### Usage

```bash
# Basic: SIP open to the world, fail2ban catches brute-force
sudo ./harden-freeswitch.sh

# Better: restrict SIP signaling to known source IPs
sudo SIP_ALLOW_FROM="203.0.113.0/24,198.51.100.7" ./harden-freeswitch.sh

# If you manage your firewall elsewhere (cloud security groups, etc.)
sudo SKIP_FIREWALL=1 ./harden-freeswitch.sh

# Skip fail2ban (e.g. if you're using crowdsec instead)
sudo SKIP_FAIL2BAN=1 ./harden-freeswitch.sh
```

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `SIP_ALLOW_FROM` | *(empty — open to world)* | Comma-separated IPs/CIDRs allowed to reach SIP ports 5060/5061/5080 |
| `SKIP_FIREWALL` | `0` | Set to `1` to skip ufw configuration |
| `SKIP_FAIL2BAN` | `0` | Set to `1` to skip fail2ban install/config |

### What it does

1. Detects whether you have a package install (`/etc/freeswitch`) or source install (`/usr/local/freeswitch/etc/freeswitch`)
2. Backs up the entire config dir to `/root/freeswitch-config-backup-TIMESTAMP.tgz`
3. Generates two random ~28-char passwords with `openssl rand`
4. Replaces `default_password=1234` in `vars.xml` (the shared SIP password for demo extensions 1000–1019)
5. Replaces the Event Socket password (`ClueCon`) and binds ESL to `127.0.0.1`
6. Writes both passwords to `/root/freeswitch-credentials.txt` (mode 600)
7. Installs `fail2ban`, drops in a freeswitch jail (5 failures in 10 min → 1 hour ban)
8. Configures `ufw`: deny incoming, allow SSH, allow RTP `16384–32768/udp`, allow SIP (optionally restricted by source IP)
9. Reloads FreeSWITCH using the *previous* ESL password (so the reload itself succeeds), then writes `/etc/fs_cli.conf` and `~SUDO_USER/.fs_cli_conf` with the new password so `fs_cli` keeps working
10. Sanity-checks `fs_cli` connectivity and reports if anything is wrong

### What it does *not* do

These are intentionally left to you:

- **Per-extension SIP passwords.** It only changes the shared `default_password`. For any real deployment, edit `/etc/freeswitch/directory/default/100X.xml` and give each user their own password.
- **Dialplan restrictions.** The default `public.xml` will route outbound calls if you configure a gateway. Toll fraud is the #1 way people lose money on FreeSWITCH boxes — review `/etc/freeswitch/dialplan/` carefully and never configure outbound PSTN until you've locked the dialplan down.
- **SIP-TLS / SRTP.** Plain SIP and RTP are unencrypted. For real use, enable TLS on port 5061 with a Let's Encrypt cert and turn on SRTP.
- **Module pruning.** It doesn't disable modules, since which ones you use is specific to your deployment. Review `/etc/freeswitch/autoload_configs/modules.conf.xml` and comment out anything you don't need.

### Important caveats

- **`ufw` is reset.** If you have existing `ufw` rules they will be wiped. Use `SKIP_FIREWALL=1` or review the script first.
- **SSH stays open.** The `OpenSSH` profile is allowed before ufw is enabled, so your current session won't drop. If you use a non-standard SSH port, edit the script to allow that port explicitly *before* running it.
- **The script is idempotent on re-run.** It reads the *current* ESL password from the config file before changing it, so you can run it again to rotate credentials or repair `fs_cli` without breaking anything.
- **Keep the credentials file.** `/root/freeswitch-credentials.txt` is the only place the new SIP password is recorded — without it, your existing SIP clients can't re-register.

---

## Recommended next steps after hardening

In rough priority order:

1. **Set per-extension passwords.** Edit each `100X.xml` in `/etc/freeswitch/directory/default/` and replace `$${default_password}` with a unique random password.
2. **Lock down the dialplan.** Remove or restrict the `outbound` extension in `default.xml`. Don't configure any SIP gateway until this is done.
3. **Enable SIP-TLS + SRTP.** Get a cert (`certbot`), point your TLS profile at it, set `rtp-secure-media=mandatory` in your sofia profile.
4. **Set up monitoring.** Alert on outbound call volume — any sudden spike (especially overnight or on weekends) is fraud in progress.
5. **Subscribe to security advisories.** <https://github.com/signalwire/freeswitch/security/advisories>
6. **Regular config backups.** `tar czf /root/fs-config-$(date +%F).tgz /etc/freeswitch` on a cron, ideally pushed off-box.

## Compatibility matrix

| OS | `install-freeswitch.sh` | `install-freeswitch-token.sh` | `harden-freeswitch.sh` |
| --- | --- | --- | --- |
| Debian 12 (Bookworm) | ✅ | ✅ | ✅ |
| Debian 13 (Trixie) | not tested  | ⚠️ needs pcre2 patch + master branch | ❌ repo not populated | ✅ |
| Ubuntu 22.04 |  not tested  | ⚠️ best-effort with `CODENAME=bookworm` | ✅ |
| Ubuntu 24.04 |  not tested  | ⚠️ best-effort with `CODENAME=bookworm` | ✅ |

## Troubleshooting

**`fs_cli` exits with `Error Connecting []`**
You changed the ESL password without updating `/etc/fs_cli.conf`. Re-run `harden-freeswitch.sh` — it's safe to run again and will repair the config.

**`E: Unable to locate package freeswitch-meta-all`**
You're on Debian 13 or a codename SignalWire doesn't publish for. Either reinstall the OS as Debian 12, or switch to `install-freeswitch.sh`.

**`apt-get update` fails with 401 from `freeswitch.signalwire.com`**
Your token is wrong or expired. Regenerate one in your SignalWire dashboard and update `/etc/apt/auth.conf.d/signalwire.conf`.

**Calls connect but there's no audio**
Almost always a firewall or NAT issue with the RTP range (`16384–32768/udp`). Check `ufw status` and any upstream cloud security groups.

## License

MIT — do whatever you want, no warranty. See `LICENSE` if present.
