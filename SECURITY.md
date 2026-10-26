# Security model

Healer lets a language model investigate production servers. This page covers what stops that from going wrong,
and what doesn't.

## Trust boundaries

| Actor | Holds | Can do |
|---|---|---|
| The model (Claude Code as `healer-ai`) | `healer_ro` key only; its only allowed tool is `Bash(px:*)` | Run commands that **healer-gate ro** allows on the Proxmox hosts in your hosts file |
| `healer.py` (root on the healer machine) | `healer_rw` key | Run a plan's fix commands that are SAFE-listed or human-approved, through **healer-gate rw** |
| You | the web sign-in / view key, approve links | Approve or reject a proposed fix |
| Your monitor | `HEALER_TOKEN` | Open incidents (it can't approve anything) |

The gate runs on each Proxmox host as an SSH forced command (`command=…,restrict`), so it holds
even if the healer machine, the prompt or the model is compromised. The `restrict` option turns
off port, agent and X11 forwarding and PTYs.

## What the gate enforces

**In both modes (hard deny):** guest and host lifecycle (`pct/qm start|stop|reboot|set|destroy|…`,
`onboot`, `reboot`, `shutdown`); destructive storage, data and account commands (`zfs destroy`,
`mkfs`, `dd`, `DROP TABLE`, `useradd`, `passwd`, …); and the **exposure lock**: no Tailscale
Funnel/Serve or settings changes, no Cloudflare tunnel routes, no firewall openings, no
`pvesh set`, no reverse tunnels (`ssh -R`, `socat`, `ngrok`, `frp`).

**Read-only mode** (the model's key) is an allow-list:
- Each pipe segment must start with a known read command. No `;`, `&&`, `||`, redirects, `tee`,
  `sed -i`, backticks, `$(…)`, newlines, or background `&`.
- Commands that can write or execute are pinned to read-only arguments. For example:
  `find` (no `-exec/-delete/-fprint`), `awk` (no `system()`, `getline` or pipes),
  `sqlite3` (only `-readonly`, no dot-commands), `curl` (GET to http(s) only, output to
  `/dev/null` only), `ip` (show only), `hostname`/`date`/`mount` (show only), `journalctl`
  (no vacuum/rotate), `openssl` (x509/s_client/verify), `ssh-keygen` (fingerprints only).
- **Secret paths can't be read:** `/etc/shadow`, `/etc/pve/priv`, private keys, `.env`
  files, `/proc/*/environ`, `.pgpass`/`.netrc`/`.git-credentials`, `/etc/ssl/private`. `docker
  inspect` is not allowed because it prints container environment variables.

**Read-write mode** (the daemon's key): the hard deny-list, plus no writes that touch
`authorized_keys`, `/etc/passwd|shadow|group|sudoers`, or proxy/tunnel/firewall config.

Every decision is logged to `/var/log/healer-gate.log` on the host.

## What it does NOT protect against

- **Data you send to the model provider.** Log lines, configs, `systemctl show/cat` output (which
  can include `Environment=` values) and query results all go to Anthropic. Keep secrets in
  files the gate refuses (`.env`, `EnvironmentFile=` under a path you add to
  `/etc/healer/gate-deny-read`), and think twice before pointing Healer at hosts with personal
  data. `sqlite3 -readonly` can still *read* any table.
- **A malicious approver.** Read-write mode is a deny-list, not an allow-list: an approved plan
  can run any command that isn't on it. The approve page shows every command before you press
  the button, so read it.
- **Your own SAFE patterns.** `HEALER_SAFE_EXTRA` and playbook `fix` lists auto-run without you.
  Keep them to idempotent restarts of things that already exist.
- **Resource use by read commands.** A read-only command can still be slow or noisy (a big `find`
  or `du`). Commands are not rate-limited beyond one investigation at a time.
- **Host-level escalation inside guests.** `pct exec` runs as root in the container. The gate
  checks the command string, not what a binary inside the guest does.

## Operating it safely

- Run `gate/test_gate.py` after every change to the gate, and add a case for every new rule.
- Keep the web UI on your LAN or behind your VPN. If you expose it, put it behind a reverse proxy
  with TLS, set `HEALER_TRUST_PROXY=1`, and use a long `HEALER_WEB_PASS`.
- Alerts contain host names, IPs and diagnoses. Send them somewhere private.
- Rotate `HEALER_TOKEN`/`HEALER_VIEW_TOKEN` if an alert email is forwarded outside your team.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository instead of a public issue.
A gate bypass (a command the model can run that it shouldn't) is the most valuable report:
include the exact command string and the mode.
