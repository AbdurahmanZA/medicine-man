# Security model

Medicine Man lets a language model investigate production servers. This page covers what stops that from going wrong,
and what doesn't.

## Trust boundaries

| Actor | Holds | Can do |
|---|---|---|
| The model (Claude Code as `healer-ai`) | `healer_ro` key only; its only tool is `Bash(px:*)` (Read, Grep, Glob, Write, Edit, web and sub-agent tools are disabled, so it can't read files on the healer machine either) | Run commands that **healer-gate ro** allows on the Proxmox hosts in your hosts file |
| `healer.py` (root on the healer machine) | `healer_rw` key | Run a plan's fix commands that are SAFE-listed or human-approved, through **healer-gate rw** |
| You | the web sign-in / view key, approve links | Approve or reject a proposed fix |
| Your monitor | `HEALER_TOKEN` | Open incidents (it can't approve anything) |

The gate runs on each Proxmox host as an SSH forced command (`command=…,restrict`), so it holds
even if the prompt or the model is manipulated: prompt injection through a log line or a guest's
files can only ask for commands, and the host decides. The `restrict` option turns off port, agent
and X11 forwarding and PTYs.

**The healer machine itself is the crown jewel.** It holds `healer_rw`, and read-write mode is a
deny-list, so whoever owns that machine can run almost anything as root on your hosts (except the
hard-denied lifecycle, exposure and destructive commands). Treat it like a jump host: its own small
VM or CT, no other services, patched, and reachable only from your LAN or VPN. If you want more,
protect `healer_rw` with a passphrase held by an ssh-agent, or keep the RW key off the machine and
approve fixes from where it lives.

## What the gate enforces

**In both modes (hard deny):** guest and host lifecycle (`pct/qm start|stop|reboot|set|destroy|…`,
`onboot`, `reboot`, `shutdown`); destructive storage, data and account commands (`zfs destroy`,
`mkfs`, `dd`, `DROP TABLE`, `useradd`, `passwd`, …); and the **exposure lock**: no Tailscale
Funnel/Serve or settings changes, no Cloudflare tunnel routes, no firewall openings, no
`pvesh set`, no reverse tunnels (`ssh -R`, `socat`, `ngrok`, `frp`).

**Read-only mode** (the model's key) is an allow-list. It is checked against what bash will
actually run:
- Each pipe segment must start with a known read command, given by name (a path like
  `/tmp/cat` is refused, because a guest could plant a binary the host can see). No `;`, `&&`,
  `||`, redirects, `tee`, `sed -i`, backticks, `$(…)`, newlines, control characters or `&`.
- No shell expansion outside single quotes: globs, `~`, `$`, backslashes and `{a,b}` are refused,
  so a secret path can't hide as `/etc/sha?ow`. Paths are normalised (`//`, `/./`, `/x/../`)
  before the secret-path check.
- Subcommands are found after any flags: `systemctl --no-pager restart x` is a restart, refused.
- Commands that can write or execute are pinned to read-only arguments. For example:
  `find` (no `-exec/-delete/-fprint`), `awk` (no `system()`, `getline`, pipes, `-i inplace`,
  extensions or program files), `curl` (GET to http(s) only, output to `/dev/null` only, no
  `@file` values), `ip` (show only, no batch mode), `sort` (no `-o`, no compress program),
  `hostname`/`date`/`mount` (show only, no `date -f`), `journalctl` (no vacuum/rotate), `openssl`
  (x509/s_client/verify), `ssh-keygen` (fingerprints only), `grep -r` (only under log and
  service-definition directories). `sqlite3` is not available at all: its dot-commands and
  `writefile()` can run commands or write files in ways an argument check can't see.
- **Secret paths can't be read:** `/etc/shadow`, `/etc/pve/priv`, private keys, `.env`
  files, `/proc/*/environ`, `.pgpass`/`.netrc`/`.git-credentials`, `/etc/ssl/private`. `docker
  inspect`, `pm2 jlist/describe/show` and `ps e` are not allowed because they print process
  environments, where API keys live.

**Both modes also refuse every side door to a guest's power state:** `systemctl` power verbs even
behind flags, starting or restarting any `.target` (`kexec.target` and `exit.target` stop a
container just like a reboot), `pve-container@`/`qemu-server@` units, `lxc-start/stop/…`, and
`kill`/`pkill`/`killall`.

**Read-write mode** (the daemon's key): the hard deny-list, plus no writes that touch
`authorized_keys`, `/etc/passwd|shadow|group|sudoers`, or proxy/tunnel/firewall config.

Every decision is logged to `/var/log/healer-gate.log` on the host.

## What it does NOT protect against

- **Data you send to the model provider.** Log lines, configs, `nginx -T` and `systemctl show/cat`
  output (which can include `Environment=` values and proxy auth headers) all go to Anthropic. Keep secrets in
  files the gate refuses (`.env`, `EnvironmentFile=` under a path you add to
  `/etc/healer/gate-deny-read`), and think twice before pointing Medicine Man at hosts with
  personal data.
- **A malicious approver.** Read-write mode is a deny-list, not an allow-list: an approved plan
  can run any command that isn't on it. The approve page shows every command before you press
  the button, so read it.
- **Your own SAFE patterns and exact commands.** `HEALER_SAFE_EXTRA`, playbook `fix` lists and
  `gate-ro-exact` are trusted without further checks. Keep them to idempotent restarts and fixed
  monitoring commands, never anything the AI wrote.
- **Resource use by read commands.** A read-only command can still be slow or noisy (a big `find`
  or `du`). Commands are not rate-limited beyond one investigation at a time.
- **Host-level escalation inside guests.** `pct exec` runs as root in the container. The gate
  checks the command string, not what a binary inside the guest does.

## Operating it safely

- Run `gate/test_gate.py` after every change to the gate, and add a case for every new rule.
- Keep the web UI on your LAN or behind your VPN. If you expose it, put it behind a reverse proxy
  with TLS, set `HEALER_TRUST_PROXY=1`, and use a long `HEALER_WEB_PASS`. Signing in sets a cookie
  holding the view token; rotate `HEALER_VIEW_TOKEN` to sign every browser out.
- Pin your hosts' SSH keys in `known_hosts` instead of trusting them on first use.
- Alerts contain host names, IPs and diagnoses. Send them somewhere private.
- Rotate `HEALER_TOKEN`/`HEALER_VIEW_TOKEN` if an alert email is forwarded outside your team.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository instead of a public issue.
A gate bypass (a command the model can run that it shouldn't) is the most valuable report:
include the exact command string and the mode.
