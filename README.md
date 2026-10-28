# Medicine Man

[![tests](https://github.com/AbdurahmanZA/medicine-man/actions/workflows/test.yml/badge.svg)](https://github.com/AbdurahmanZA/medicine-man/actions/workflows/test.yml) [![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

**Let an AI take the 3am call on your Proxmox servers, without ever giving it root.**

Most outages end with one command: restart the thing. Medicine Man lets
[Claude Code](https://docs.anthropic.com/en/docs/claude-code) take that first look. It reads the
logs, finds the cause, fixes the safe ones by itself, and sends you the rest with an approve button.

What makes it safe to run is the **gate**, not the prompt. A small SSH forced command on each
Proxmox host checks every command *on the host*, whatever the model asks for:

- **Read-only diagnosis.** The AI holds a read-only key and nothing else. Writes, chained
  commands, shell tricks and secret files (`.env`, private keys, `/etc/shadow`) are refused.
- **Never starts, stops or reboots a guest or host**, in either mode, including the side doors
  (`kexec.target`, `pve-container@`, `lxc-stop`, `kill`). A stopped guest may have been shut down
  on purpose, so Medicine Man reports it and leaves it alone.
- **Nothing becomes more public.** No Tailscale Funnel/Serve, tunnel routes, firewall openings,
  proxy config edits or reverse tunnels.
- **You stay in charge.** Fixes run with a separate key the AI never sees, and only if they're
  on a short safe list or you pressed *Approve*.

174 attack-style tests guard the gate. Writing them found real bypasses in an earlier version, and
an independent review found more. Every bypass found is now a test.

> The medicine man diagnoses first, treats only what is safe, and never acts without consent. So does this.

*Built and maintained by [SANDZ](https://www.sandz.co.za) · MIT licensed · Python standard library only.*

```
monitor ──POST /incident──► healer.py ──runuser healer-ai──► claude -p  (only tool: Bash(px:*))
                               │                                  │
                               │                                  └─► px <host> '<cmd>' ── ssh (healer_ro) ──┐
                               │                                                                             ▼
                               └─ safe or approved fix ── ssh (healer_rw) ─────────────► healer-gate ro|rw on the Proxmox host
                                                                                               (allow / deny, logged)
```

## What's in the box

| Path | What it is |
|---|---|
| `gate/healer-gate.py` | The SSH forced command. Read-only mode is an allow-list; read-write mode is a hard deny-list. |
| `gate/test_gate.py` | 174 attack-style cases: lifecycle, destruction, write and exec bypasses, shell expansion, secret reads, exposure. |
| `bin/px` | The AI's only tool: `px <host> '<cmd>'` over the read-only key. |
| `healer/healer.py` | The daemon: incidents, diagnosis, SAFE classifier, approvals, re-probe, alerts, incident page. |
| `healer/playbooks.py` | Optional per-app playbooks: what to look at, and the *only* fixes allowed for each check. |
| `examples/` | Hosts file, env, authorized_keys, playbooks, gate extensions, an incident, a send script. |

## How a fix is decided

1. The model proposes a plan in JSON: diagnosis, root cause, confidence, and the fix commands.
   Its output is treated as untrusted and cleaned before anything reads it.
2. A fix **runs automatically** only if confidence is medium or high, *every* command fully
   matches the SAFE list (restart a `.service` or pm2 process or container inside a CT, vacuum
   journald, `apt-get clean`, restart the PVE daemons), and, for a playbook incident, every
   command is in that check's own `fix` list on its own host.
3. Anything else becomes **"Needs your OK"**. The alert links to a confirm page that shows each
   command and the host it runs on. Nothing runs until you press the button (opening the link
   isn't enough, so mail link scanners can't approve fixes), and a plan can only be approved once.
4. After a fix, Medicine Man re-runs the check that failed (`probe` in the incident, or your
   monitor's re-probe URL) and reports *Healed*, *Fix failed*, or *Applied, not verified*.
5. Restarting `tailscaled`/`cloudflared` for a public-URL incident (key ending in `|public`)
   always needs approval, because it drops every inbound connection and rarely helps a relay blip.

## Install

You need: a small Debian/Ubuntu VM or LXC for the daemon (it doesn't need to be a Proxmox host),
Python 3.9+, OpenSSH client, and Claude Code installed for the AI user (a Claude subscription
login or an API key).

**1. On the healer machine**
```bash
git clone <this repo> /opt/healer
useradd --create-home --shell /bin/bash healer-ai
install -m 755 /opt/healer/bin/px /usr/local/bin/px
install -d -m 755 /etc/healer                     # healer-ai must be able to read the hosts file
install -d -m 700 /var/lib/healer
cp /opt/healer/examples/hosts.example /etc/healer/hosts            # edit: your Proxmox hosts
cp /opt/healer/examples/healer.env.example /etc/healer/healer.env  # edit: tokens, password, alerts
chmod 644 /etc/healer/hosts; chmod 600 /etc/healer/healer.env
cp /opt/healer/examples/playbooks.example.json /etc/healer/playbooks.json   # optional

# two keys: the AI gets read-only, root keeps read-write
sudo -u healer-ai ssh-keygen -t ed25519 -N '' -C healer-ro -f /home/healer-ai/.ssh/healer_ro
ssh-keygen -t ed25519 -N '' -C healer-rw -f /root/.ssh/healer_rw

# install Claude Code for healer-ai and log in once (or put a token in /etc/healer/claude.env).
# If `claude` isn't in ~/.local/bin or /usr/local/bin, set HEALER_CLAUDE_BIN to its full path.
su - healer-ai -c claude
```

**2. On each Proxmox host**
```bash
install -m 755 /opt/healer/gate/healer-gate.py /usr/local/bin/healer-gate   # copy it over first
# add both public keys with the forced command, see examples/authorized_keys.example
```
Pin the hosts' SSH keys up front (`ssh-keyscan <host> >> ~/.ssh/known_hosts` for both healer-ai
and root, then check the fingerprints) instead of trusting them on first use.

**3. Check the gate before anything else**
```bash
python3 /opt/healer/gate/test_gate.py                       # expect: failures: 0
sudo -u healer-ai px pve1 'pct list'                         # allowed
sudo -u healer-ai px pve1 'pct start 101'                    # DENIED (hard-deny)
sudo -u healer-ai px pve1 'cat /etc/shadow'                  # DENIED (secret path)
tail /var/log/healer-gate.log                                # on the Proxmox host
```

**4. Start the daemon**
```bash
cp /opt/healer/systemd/healer.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now healer
curl -s http://127.0.0.1:3050/health                         # "claude_auth": true
```

## Sending incidents

Any monitor that can POST JSON (Uptime Kuma webhooks, a cron script, your own checker) works:

```bash
curl -X POST http://healer.lan:3050/incident -H "X-Healer-Token: $HEALER_TOKEN" \
     -H "Content-Type: application/json" --data-binary @examples/incident.example.json
```

| Field | Required | Meaning |
|---|---|---|
| `key` | yes | Stable id for this check. Repeats within `HEALER_COOLDOWN_S` (1 h) are ignored. End it with `|public` for public-URL checks. |
| `label`, `ip`, `detail` | | What's down and what the probe saw. |
| `host`, `ctid`, `check` | | Where it lives. `ctid` + `check` select a playbook. |
| `probe` | | How to re-check after a fix: `{"http": "https://..."}` (http/https only, `expect` = status list) or `{"tcp": "host:port"}`. |
| `context` | | Anything that helps the diagnosis (up to 8000 characters of JSON): stack, ports, what *should* be public. |

## Configuration

All settings are environment variables in `/etc/healer/healer.env`; see
`examples/healer.env.example` for the full list. The most important:

| Variable | Default | |
|---|---|---|
| `HEALER_TOKEN` | — | Monitor → Medicine Man token (required to accept incidents) |
| `HEALER_VIEW_TOKEN`, `HEALER_WEB_USER`, `HEALER_WEB_PASS` | — / `admin` / — | Incident page sign-in. Rotate the view token to sign every browser out. |
| `HEALER_BIND`, `PORT` | `127.0.0.1`, `3050` | Listen address. Keep it on your LAN or VPN; approve links must be reachable from where you read alerts. |
| `HEALER_PUBLIC_BASE` | `http://127.0.0.1:3050` | Base URL used in alert links |
| `HEALER_MODEL`, `HEALER_ESCALATE_MODEL` | `haiku`, — | Triage model, and optional bigger model for low-confidence answers |
| `HEALER_CLAUDE_BIN` | `claude` | Path to Claude Code if it isn't on the AI user's PATH |
| `HEALER_SMTP_*`, `HEALER_EMAIL_*`, `HEALER_WEBHOOK_URL` | — | Where alerts go |
| `HEALER_SAFE_EXTRA` | `/etc/healer/safe-extra` | Extra auto-run regexes |
| `HEALER_PLAYBOOKS` | `/etc/healer/playbooks.json` | Per-app playbooks |

Gate extensions on each Proxmox host, all optional:
- `/etc/healer/gate-ro-extra`: your own read-only check scripts (by command name).
- `/etc/healer/gate-deny-read`: more paths the AI must never read.
- `/etc/healer/gate-ro-exact`: exact commands your *monitoring* sends that need globs or awk.

## Costs and privacy

Each incident is one Claude Code run (up to `HEALER_MAX_TURNS`, default 20). The default `haiku`
model keeps a typical diagnosis cheap. **Everything the AI reads is sent to Anthropic**: logs,
configs, command output. The gate blocks the obvious secrets, but read [SECURITY.md](SECURITY.md)
before pointing it at hosts that hold personal data.

## About

Medicine Man is built and maintained by **[SANDZ](https://www.sandz.co.za)**, a software studio that
builds and runs apps for small businesses on its own Proxmox estate. It started as the
on-call agent for that estate.

Found a way past the gate? That's the most useful report you can send. See [SECURITY.md](SECURITY.md).

MIT licence, see [LICENSE](LICENSE). Visit **[www.sandz.co.za](https://www.sandz.co.za)**.
