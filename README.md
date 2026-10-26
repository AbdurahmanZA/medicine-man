# Medicine Man

**A self-heal agent for Proxmox that lets an AI diagnose your servers without trusting it with root.**

When your monitor reports something down, Healer has [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
(headless) investigate over SSH, then either fixes it automatically (only for a short list of safe
fixes) or emails you the diagnosis with a one-click approve link.

What makes it safe to run is **healer-gate**: a small SSH forced command on each Proxmox host
that checks every command *on the host*, no matter what the model decides.

- The AI only ever holds a **read-only** key. Writes, chaining, and reading secrets (`.env`
  files, private keys, `/etc/shadow`) are refused.
- **Nothing ever starts, stops or reboots a guest or host**, in either mode. A stopped guest may
  have been shut down on purpose, so Healer reports it and leaves it alone.
- **Nothing can become more public.** No Tailscale Funnel/Serve, tunnel routes, firewall
  openings, proxy config edits or reverse tunnels.
- Fixes run with a separate key the AI never sees, and only if they're on the SAFE list or a human approved them.

> The medicine man diagnoses first, treats only what is safe, and never acts without consent. So does this.

```
monitor ──POST /incident──► healer.py ──runuser healer-ai──► claude -p  (allowed tool: Bash(px:*))
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
| `gate/test_gate.py` | 118 attack-style cases: lifecycle, destruction, write bypasses, secret reads, exposure. |
| `bin/px` | The AI's only tool: `px <host> '<cmd>'` over the read-only key. |
| `healer/healer.py` | The daemon: incidents, diagnosis, SAFE classifier, approvals, re-probe, alerts, incident page. Python stdlib only. |
| `healer/playbooks.py` | Optional per-app playbooks: what to look at, and the *only* fixes allowed for each check. |
| `examples/` | Hosts file, env, authorized_keys, playbooks, an incident, a send script. |

## How a fix is decided

1. The model proposes a plan in JSON: diagnosis, root cause, confidence, and the fix commands.
2. A fix **runs automatically** only if confidence is medium or high, *every* command fully
   matches the SAFE list (restart a unit/pm2 process/container inside a CT, vacuum journald,
   `apt-get clean`, restart the PVE daemons), and, for a playbook incident, every command is in
   that check's own `fix` list on its own host.
3. Anything else becomes **"Needs your OK"**. The alert links to a confirm page, and nothing runs
   until you press the button (opening the link isn't enough, so mail link scanners can't approve fixes).
4. After a fix, Healer re-runs the check that failed (`probe` in the incident, or your monitor's
   re-probe URL) and reports *Healed*, *Fix failed*, or *Applied, not verified*.
5. Restarting `tailscaled`/`cloudflared` for a public-URL incident (key ending in `|public`)
   always needs approval, because it drops every inbound connection and rarely helps a relay blip.

## Install

You need: a small Debian/Ubuntu VM or LXC for the daemon (it doesn't need to be a Proxmox host),
Python 3.9+, OpenSSH client, and Claude Code on that machine
(a Claude subscription login or an API key).

**1. On the healer machine**
```bash
git clone <this repo> /opt/healer
useradd --create-home --shell /bin/bash healer-ai
install -m 755 /opt/healer/bin/px /usr/local/bin/px
install -d -m 700 /etc/healer /var/lib/healer
cp /opt/healer/examples/hosts.example /etc/healer/hosts            # edit: your Proxmox hosts
cp /opt/healer/examples/healer.env.example /etc/healer/healer.env  # edit: tokens, password, alerts
chmod 600 /etc/healer/healer.env; chmod 644 /etc/healer/hosts
cp /opt/healer/examples/playbooks.example.json /etc/healer/playbooks.json   # optional

# two keys: the AI gets read-only, root keeps read-write
sudo -u healer-ai ssh-keygen -t ed25519 -N '' -C healer-ro -f /home/healer-ai/.ssh/healer_ro
ssh-keygen -t ed25519 -N '' -C healer-rw -f /root/.ssh/healer_rw

# log the AI user in to Claude Code once (or put a token in /etc/healer/claude.env)
su - healer-ai -c claude
```

**2. On each Proxmox host**
```bash
install -m 755 healer-gate.py /usr/local/bin/healer-gate
# add both public keys with the forced command, see examples/authorized_keys.example
```

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
| `probe` | | How to re-check after a fix: `{"http": "...", "expect": [200]}` or `{"tcp": "host:port"}`. |
| `context` | | Anything that helps the diagnosis: stack, ports, what *should* be public. |

## Configuration

All settings are environment variables in `/etc/healer/healer.env`; see
`examples/healer.env.example` for the full list. The most important:

| Variable | Default | |
|---|---|---|
| `HEALER_TOKEN` | — | Monitor → Healer token (required to accept incidents) |
| `HEALER_VIEW_TOKEN`, `HEALER_WEB_USER`, `HEALER_WEB_PASS` | — / `admin` / — | Incident page sign-in |
| `HEALER_BIND`, `PORT` | `127.0.0.1`, `3050` | Listen address. Approve links must be reachable from where you read alerts. |
| `HEALER_PUBLIC_BASE` | `http://127.0.0.1:3050` | Base URL used in alert links |
| `HEALER_MODEL`, `HEALER_ESCALATE_MODEL` | `haiku`, — | Triage model, and optional bigger model for low-confidence answers |
| `HEALER_SMTP_*`, `HEALER_EMAIL_*`, `HEALER_WEBHOOK_URL` | — | Where alerts go |
| `HEALER_SAFE_EXTRA` | `/etc/healer/safe-extra` | Extra auto-run regexes |
| `HEALER_PLAYBOOKS` | `/etc/healer/playbooks.json` | Per-app playbooks |

Gate extensions on each Proxmox host: `/etc/healer/gate-ro-extra` (your own read-only check
scripts) and `/etc/healer/gate-deny-read` (more paths the AI must never read).

## Costs and privacy

Each incident is one Claude Code run (up to `HEALER_MAX_TURNS`, default 20). The default `haiku`
model keeps a typical diagnosis cheap. **Everything the AI reads is sent to Anthropic**: logs, configs, command output.
The gate blocks the obvious secrets, but read [SECURITY.md](SECURITY.md) before
pointing it at hosts that hold personal data.

## Licence

MIT. See [LICENSE](LICENSE). Built by [SANDZ](https://www.sandz.co.za).
