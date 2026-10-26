#!/usr/bin/env python3
"""Medicine Man: a self-heal agent for Proxmox.

Your monitor POSTs an incident when something goes down. Healer has Claude Code (headless)
diagnose it over a READ-ONLY, gated SSH key, then either auto-applies a fix that matches the
SAFE list, or sends you an approve link. Every command is checked again on the Proxmox host by
healer-gate, independent of the model.

Rules, enforced three times (prompt, the SAFE classifier here, healer-gate on each host):
  * never start, stop or reboot a guest or host - it may have been shut down on purpose;
  * never change what is exposed to the internet;
  * safe fixes run automatically (restart a service/process/container inside a running guest,
    vacuum logs); everything else waits for a human to approve.

Endpoints (HEALER_BIND:PORT, default 127.0.0.1:3050):
  GET  /health
  POST /incident          (X-Healer-Token) {key, label, ip, detail, host?, ctid?, check?, probe?, context?}
  POST /diagnose?key=&label=&ip=&detail=   manual trigger (token)
  GET  /incidents         incident list (sign-in or view key)
  GET  /approve/<id>?t=   confirm page   POST /approve/<id>  run the plan
  GET  /reject/<id>?t=    confirm page   POST /reject/<id>   discard it
"""
import os, re, json, time, sqlite3, secrets, shutil, socket, smtplib, subprocess, threading, html
import urllib.request, urllib.parse, urllib.error
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import playbooks

env = os.environ.get
BIND        = env("HEALER_BIND", "127.0.0.1")
PORT        = int(env("PORT", "3050"))
DB          = env("HEALER_DB", "/var/lib/healer/healer.db")
TOKEN       = env("HEALER_TOKEN", "")          # monitor -> /incident, /diagnose
# Read-only key for the incident page. Alert links carry it as ?v=, the first click turns it into
# a cookie. Separate from TOKEN so a forwarded email can't trigger anything.
VIEW_TOKEN  = env("HEALER_VIEW_TOKEN", "")
WEB_USER    = env("HEALER_WEB_USER", "admin")
WEB_PASS    = env("HEALER_WEB_PASS", "")
TRUST_PROXY = env("HEALER_TRUST_PROXY", "") == "1"   # honour X-Forwarded-For (only behind your own proxy)
PUBLIC_BASE = env("HEALER_PUBLIC_BASE", "http://127.0.0.1:3050").rstrip("/")
HOSTS_FILE  = env("HEALER_HOSTS_FILE", "/etc/healer/hosts")
SAFE_EXTRA  = env("HEALER_SAFE_EXTRA", "/etc/healer/safe-extra")
REPROBE_URL = env("HEALER_REPROBE_URL", "")    # optional: GET ?key=&ip=&label= -> {"ok": bool, "detail": str}
RW_KEY      = env("HEALER_RW_KEY", "/root/.ssh/healer_rw")
AI_USER     = env("HEALER_AI_USER", "healer-ai")
CLAUDE_BIN  = env("HEALER_CLAUDE_BIN", "claude")   # full path if `claude` isn't on the AI user's PATH
COOLDOWN_S  = int(env("HEALER_COOLDOWN_S", "3600"))
MAX_TURNS   = env("HEALER_MAX_TURNS", "20")
SETTLE_S    = int(env("HEALER_SETTLE_S", "45"))  # wait after a fix before re-probing
# Cheap by default: a small model triages. Optional one-shot escalation to a bigger model only
# when the first answer is low-confidence and HEALER_ESCALATE_MODEL is set.
MODEL          = env("HEALER_MODEL", "haiku")
ESCALATE_MODEL = env("HEALER_ESCALATE_MODEL", "")
SMTP_HOST   = env("HEALER_SMTP_HOST", "")
SMTP_PORT   = int(env("HEALER_SMTP_PORT", "587"))
SMTP_USER   = env("HEALER_SMTP_USER", "")
SMTP_PASS   = env("HEALER_SMTP_PASS", "")
SMTP_TLS    = env("HEALER_SMTP_TLS", "starttls")   # starttls | ssl | none
EMAIL_FROM  = env("HEALER_EMAIL_FROM", "")
EMAIL_TO    = env("HEALER_EMAIL_TO", "")
WEBHOOK_URL = env("HEALER_WEBHOOK_URL", "")    # POST {"text": "..."} (Slack/Mattermost/Discord-compatible)


def load_hosts():
    """name -> address, from the same file px uses ("name address" or "name=address" per line)."""
    hosts = {}
    try:
        with open(HOSTS_FILE) as f:
            for line in f:
                t = line.split("#", 1)[0].replace("=", " ", 1).split()
                if len(t) >= 2:
                    hosts[t[0]] = t[1]
    except OSError:
        pass
    return hosts


HOSTS = load_hosts()

# A fix command auto-runs only if it FULLY matches one of these. Everything else -> approval.
SAFE = [
    # Unit names without dots, or ending in .service: never a .target (kexec.target stops the guest).
    r"pct exec \d+ -- systemctl (restart|reload|reset-failed) [\w@\-]+(\.service)?",
    r"pct exec \d+ -- pm2 (restart|reload) [\w.\-]+",
    r"pct exec \d+ -- docker restart [\w.\-]+",
    r"pct exec \d+ -- journalctl --vacuum-(size|time)=\w+",
    r"pct exec \d+ -- apt-get clean",
    r"pct exec \d+ -- nginx -t",
    r"systemctl (restart|reload) (pveproxy|pvestatd|pvedaemon|pve-firewall)",
]
try:
    with open(SAFE_EXTRA) as f:
        SAFE += [x.strip() for x in f if x.strip() and not x.startswith("#")]
except OSError:
    pass
NEVER = (r"\b(pct|qm)\s+(start|stop|shutdown|reboot|resume|destroy|set|create|restore|rollback)\b|\bonboot\b|\breboot\b"
         r"|\bpoweroff\b|\btailscale\s+(serve|funnel|set)\b|\bcloudflared\b.*\btunnel\b|\bufw\s+allow\b|\biptables\s+-[AI]\b"
         r"|/etc/(nginx|cloudflared)|[;&|`\n]|\$\(|\.target\b|\b(pve-container|qemu-server)@|\blxc-|\b(kill|killall|pkill|kexec)\b")

LOCK = threading.Lock()
COLS = ["id", "ts", "key", "label", "ip", "detail", "host", "ctid", "check_name", "probe", "context",
        "status", "diagnosis", "plan", "token", "result", "updated"]


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.execute("""CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, ts INTEGER, key TEXT,
        label TEXT, ip TEXT, detail TEXT, host TEXT, ctid TEXT, check_name TEXT, probe TEXT, context TEXT,
        status TEXT, diagnosis TEXT, plan TEXT, token TEXT, result TEXT, updated INTEGER)""")
    return c


def get_incident(c, inc_id):
    row = c.execute("SELECT %s FROM incidents WHERE id=?" % ",".join(COLS), (inc_id,)).fetchone()
    if not row:
        return None
    inc = dict(zip(COLS, row))
    inc["check"] = inc.pop("check_name")
    for k in ("probe", "context"):
        inc[k] = json.loads(inc[k] or "null")
    return inc


def notify(subject, text):
    if SMTP_HOST and EMAIL_TO and EMAIL_FROM:
        try:
            m = EmailMessage()
            m["From"], m["To"], m["Subject"] = EMAIL_FROM, EMAIL_TO, subject[:200]
            m.set_content(text)
            cls = smtplib.SMTP_SSL if SMTP_TLS == "ssl" else smtplib.SMTP
            with cls(SMTP_HOST, SMTP_PORT, timeout=25) as s:
                if SMTP_TLS == "starttls":
                    s.starttls()
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(m)
        except Exception as e:
            print("email failed: %s" % e, flush=True)
    if WEBHOOK_URL:
        try:
            req = urllib.request.Request(WEBHOOK_URL, method="POST", headers={"Content-Type": "application/json"},
                                         data=json.dumps({"text": ("[Healer] " + subject + "\n" + text)[:3500]}).encode())
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            print("webhook failed: %s" % e, flush=True)


def same(a, b):
    """Constant-time compare that also copes with non-ASCII input (compare_digest on str raises)."""
    return secrets.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def is_safe(cmd):
    if re.search(NEVER, cmd, re.I):
        return False
    return any(re.fullmatch(p, cmd.strip()) for p in SAFE)


PROMPT = """You are the self-heal agent for a Proxmox estate. A monitor reported:

  SERVICE: {label}
  IP:      {ip}
  PROBE:   {detail}
  CONTEXT: {context}

Investigate the root cause using ONLY the `px` command:  px <host> '<command>'
Proxmox hosts: {hosts}. Guests are reached with `px <host> 'pct exec <ctid> -- <cmd>'`
(find which host a CT lives on with `px <host> 'pct list'`). Access is READ-ONLY and filtered:
journalctl, systemctl status, pm2 jlist/logs, df, free, ss, ps, cat/tail/grep of logs, nginx -t,
zfs/zpool list/status, curl -s GET. Writes, chaining (; && > tee) and reading secrets (.env files,
private keys, /etc/shadow) are refused - don't try.

HARD RULES
 - NEVER propose starting, stopping, rebooting or changing onboot of any guest or host
   (pct/qm start|stop|reboot|set). If a guest is STOPPED, say so: the operator may have
   shut it down on purpose. Report it; do not propose starting it.
 - NEVER change what is exposed to the internet: no Tailscale Funnel/Serve, no Cloudflare tunnel
   routes or config, no firewall openings, no nginx/proxy config edits. Restarting an existing
   service (cloudflared, tailscaled, nginx) is fine. It only restores what was already there.
 - If only a PUBLIC URL fails while the app answers on the LAN, it is often a relay/tunnel blip
   that clears by itself in minutes. Check the tunnel's status first; only propose restarting it
   if it is actually stopped or logged out. Otherwise propose no fix and say so.
 - Prefer the smallest fix. Typical safe fixes: restart one systemd unit / pm2 process /
   docker container inside a running CT; vacuum journald; apt-get clean.
 - Each fix command must be ONE command, no chaining, in the exact form run on the Proxmox host,
   e.g. `pct exec 101 -- systemctl restart nginx`.
 - If you are not confident, propose no fix and explain what a human should look at.

Finish with ONLY this JSON in a ```json block:
{{"diagnosis": "...what you found, with the evidence lines...",
  "root_cause": "...one sentence...",
  "confidence": "low|medium|high",
  "guest_stopped": true|false,
  "fix": [{{"host": "pve1", "cmd": "pct exec 101 -- systemctl restart nginx", "why": "..."}}],
  "operator_note": "...anything the human should do that you may not..."}}
"""

PLAYBOOK_PROMPT = """
THIS IS AN APP COMPONENT CHECK with a playbook. App: {app}
Failed check: "{check}" - {means}
Look at first (prefix with `pct exec {ctid} -- ` unless it is a host command): {look}
The ONLY fixes allowed for this check (copy one EXACTLY, host "{host}"): {fix}
Conditions: {note}
If none of the allowed fixes fits the evidence, propose no fix and explain.
"""


def run_claude(inc, model=None):
    prompt = PROMPT.format(label=inc["label"], ip=inc["ip"], detail=inc["detail"],
                           context=json.dumps(inc.get("context") or {}),
                           hosts=", ".join("%s (%s)" % kv for kv in HOSTS.items()) or "(none configured)")
    pb = playbooks.for_incident(inc)
    if pb:
        ctid, check, host, app, book = pb
        prompt += PLAYBOOK_PROMPT.format(app=app, check=check, means=book.get("means", ""), ctid=ctid,
                                         look="; ".join(book.get("look", [])), host=host,
                                         fix=json.dumps(book.get("fix")) if book.get("fix") else "NONE (report only)",
                                         note=book.get("note") or "-")
    home = "/home/" + AI_USER
    # ~/.local/bin is where Claude Code's native installer puts `claude`.
    run_env = {"PATH": f"{home}/.local/bin:/usr/local/bin:/usr/bin:/bin", "HOME": home, "DISABLE_AUTOUPDATER": "1"}
    for k in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):   # else: the AI user's own `claude` login
        if env(k):
            run_env[k] = env(k)
    # px is the ONLY tool. Claude Code's built-in Read/Grep/Glob would otherwise let the model read
    # files on this machine, including its own read-only SSH key.
    cmd = [shutil.which("runuser") or "/usr/sbin/runuser", "-u", AI_USER, "--", CLAUDE_BIN, "-p", prompt,
           "--output-format", "json", "--model", model or MODEL, "--max-turns", MAX_TURNS,
           "--allowedTools", "Bash(px:*)",
           "--disallowedTools", "Read", "Glob", "Grep", "LS", "Task", "Agent", "Write", "Edit", "MultiEdit",
           "NotebookEdit", "NotebookRead", "WebFetch", "WebSearch", "TodoWrite"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=run_env, cwd="/home/" + AI_USER)
    out = r.stdout.strip()
    try:
        text = json.loads(out).get("result", "")
    except Exception:
        text = out or r.stderr
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S) or re.search(r"(\{\s*\"diagnosis\".*\})", text, re.S)
    try:
        plan = json.loads(m.group(1)) if m else None
    except ValueError:
        plan = None
    plan = clean_plan(plan if isinstance(plan, dict) else {"diagnosis": text[-3000:], "confidence": "low", "fix": []})
    plan["model"] = model or MODEL
    return plan


def clean_plan(p):
    """Force the model's JSON into the shape the rest of the code expects (it is untrusted output)."""
    s = lambda v, n: v[:n] if isinstance(v, str) else ("" if v is None else str(v)[:n])
    fixes = []
    for f in p.get("fix") if isinstance(p.get("fix"), list) else []:
        if isinstance(f, dict) and isinstance(f.get("cmd"), str) and isinstance(f.get("host"), str) and f["cmd"].strip():
            fixes.append({"host": f["host"][:64], "cmd": f["cmd"].strip()[:500], "why": s(f.get("why"), 500)})
    conf = p.get("confidence") if p.get("confidence") in ("low", "medium", "high") else "low"
    return {"diagnosis": s(p.get("diagnosis"), 6000), "root_cause": s(p.get("root_cause"), 500), "confidence": conf,
            "guest_stopped": bool(p.get("guest_stopped")), "fix": fixes, "operator_note": s(p.get("operator_note"), 1000)}


def apply_plan(plan):
    out = []
    for f in plan.get("fix", []):
        host = HOSTS.get(f.get("host", ""))
        if not host:
            out.append("SKIP unknown host %s" % f.get("host")); continue
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                            "-o", "ConnectTimeout=10", "-i", RW_KEY, "root@" + host, f["cmd"]],
                           capture_output=True, text=True, timeout=180)
        out.append("[%s] $ %s -> exit %d %s" % (f["host"], f["cmd"], r.returncode, (r.stdout + r.stderr).strip()[-400:]))
    return out


def reprobe(inc):
    """Check the thing that FAILED again: the incident's own probe, else HEALER_REPROBE_URL, else unknown."""
    p = inc.get("probe") or {}
    try:
        if p.get("http"):
            if not re.match(r"https?://", str(p["http"])):      # no file://, ftp:// and friends
                return False, "probe must be an http(s) URL"
            req = urllib.request.Request(p["http"], headers={"User-Agent": "healer-reprobe"})
            try:
                code = urllib.request.urlopen(req, timeout=15).status
            except urllib.error.HTTPError as e:
                code = e.code
            want = p.get("expect", [200])
            want = want if isinstance(want, list) else [want]
            return code in want, "HTTP %s from %s" % (code, p["http"])
        if p.get("tcp"):
            h, _, port = p["tcp"].rpartition(":")
            with socket.create_connection((h, int(port)), timeout=10):
                return True, "TCP %s open" % p["tcp"]
        if REPROBE_URL:
            q = urllib.parse.urlencode({"key": inc["key"], "ip": inc["ip"], "label": inc["label"]})
            with urllib.request.urlopen(REPROBE_URL + ("&" if "?" in REPROBE_URL else "?") + q, timeout=60) as r:
                d = json.load(r)
            return d.get("ok"), d.get("detail", "")
    except Exception as e:
        return False, "re-probe failed: %s" % e
    return None, "no probe configured - not verified"


def outcome(ok):
    return "healed" if ok else ("fix-failed" if ok is False else "applied")


def fmt_plan(plan):
    fixes = "\n".join("  %s  [%s] $ %s\n      why: %s" % ("AUTO " if is_safe(f.get("cmd", "")) else "NEEDS-OK",
                      f.get("host", "?"), f.get("cmd"), f.get("why", "")) for f in plan.get("fix", [])) or "  (no fix proposed)"
    return ("Model: %s · Root cause: %s\nConfidence: %s\n\nDiagnosis:\n%s\n\nProposed fix:\n%s\n\nOperator note: %s"
            % (plan.get("model", "?"), plan.get("root_cause", "?"), plan.get("confidence", "?"),
               plan.get("diagnosis", "")[:2500], fixes, plan.get("operator_note", "")))


def guarded(fn):
    """Run an incident worker; if it dies, say so on the incident instead of leaving it stuck."""
    def run(inc_id):
        try:
            fn(inc_id)
        except Exception as e:
            print("incident %s failed: %r" % (inc_id, e), flush=True)
            try:
                c = db()
                c.execute("UPDATE incidents SET status='error', result=?, updated=? WHERE id=?",
                          ("Healer error: %s" % str(e)[:500], int(time.time()), inc_id))
                c.commit(); c.close()
            except Exception:
                pass
    return run


@guarded
def handle(inc_id):
    with LOCK:      # one investigation at a time - keeps RAM and blast radius small
        c = db()
        inc = get_incident(c, inc_id)
        c.execute("UPDATE incidents SET status='diagnosing', updated=? WHERE id=?", (int(time.time()), inc_id)); c.commit()
        try:
            plan = run_claude(inc)
            if plan.get("confidence") == "low" and ESCALATE_MODEL:
                plan = run_claude(inc, ESCALATE_MODEL)
        except Exception as e:
            plan = {"diagnosis": "Healer failed to run Claude Code: %s" % e, "confidence": "low", "fix": []}
        fixes = plan.get("fix") or []
        auto = bool(fixes) and plan.get("confidence") in ("medium", "high") and all(is_safe(f.get("cmd", "")) for f in fixes)
        # App component incidents: only the playbook's own fixes, on the app's own host, may auto-run.
        pb = playbooks.for_incident(inc)
        if auto and pb:
            auto = all(f.get("cmd", "").strip() in pb[4].get("fix", []) and f.get("host") == pb[2] for f in fixes)
        # Public-URL incidents (key ends with "|public"): restarting tailscaled/cloudflared cuts every
        # inbound connection and rarely helps a relay blip, so it always needs a human OK.
        if auto and inc["key"].endswith("|public") and any(re.search(r"tailscaled|cloudflared", f.get("cmd", "")) for f in fixes):
            auto = False
        now = int(time.time())
        if auto:
            res = apply_plan(plan)
            time.sleep(SETTLE_S)
            ok, d = reprobe(inc)
            c.execute("UPDATE incidents SET status=?, diagnosis=?, plan=?, result=?, updated=? WHERE id=?",
                      (outcome(ok), plan.get("diagnosis", ""), json.dumps(plan),
                       "\n".join(res) + "\nre-probe: %s %s" % (ok, d), now, inc_id)); c.commit()
            notify({True: "Auto-healed: ", False: "Auto-fix did NOT recover: ", None: "Auto-fix applied (not verified): "}[ok]
                   + inc["label"], fmt_plan(plan) + "\n\nRan:\n" + "\n".join(res) + "\n\nRe-probe: %s\n\n%s" % (d, incident_link(inc_id)))
        elif fixes:
            c.execute("UPDATE incidents SET status='awaiting-approval', diagnosis=?, plan=?, updated=? WHERE id=?",
                      (plan.get("diagnosis", ""), json.dumps(plan), now, inc_id)); c.commit()
            notify("Fix needs your OK: " + inc["label"], fmt_plan(plan)
                   + "\n\nReview and approve: %s/approve/%d?t=%s\nReject: %s/reject/%d?t=%s"
                   % (PUBLIC_BASE, inc_id, inc["token"], PUBLIC_BASE, inc_id, inc["token"]))
        else:
            c.execute("UPDATE incidents SET status='diagnosed', diagnosis=?, plan=?, updated=? WHERE id=?",
                      (plan.get("diagnosis", ""), json.dumps(plan), now, inc_id)); c.commit()
            notify("Diagnosis: " + inc["label"], fmt_plan(plan) + "\n\n" + incident_link(inc_id))
        c.close()


@guarded
def approve(inc_id):
    with LOCK:
        c = db()
        inc = get_incident(c, inc_id)
        plan = json.loads(inc["plan"] or "{}")
        res = apply_plan(plan)          # healer-gate on each host still refuses lifecycle/exposure commands
        time.sleep(SETTLE_S)
        ok, d = reprobe(inc)
        c.execute("UPDATE incidents SET status=?, result=?, updated=? WHERE id=?",
                  (outcome(ok), "\n".join(res) + "\nre-probe: %s %s" % (ok, d), int(time.time()), inc_id))
        c.commit(); c.close()
        notify({True: "Approved fix worked: ", False: "Approved fix did not recover: ", None: "Approved fix applied: "}[ok]
               + inc["label"], "Ran:\n" + "\n".join(res) + "\n\nRe-probe: %s" % d)


def new_incident(d):
    key = str(d.get("key") or "")[:300]
    ctx = json.dumps(d.get("context")) if d.get("context") else None
    if ctx and len(ctx) > 8000:
        raise ValueError("context is larger than 8000 characters")
    c = db()
    if c.execute("SELECT id FROM incidents WHERE key=? AND ts>?", (key, int(time.time()) - COOLDOWN_S)).fetchone():
        c.close(); return None
    now = int(time.time())
    cur = c.execute("INSERT INTO incidents (ts, key, label, ip, detail, host, ctid, check_name, probe, context, status, token, updated)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (now, key, str(d.get("label") or key)[:200], str(d.get("ip") or "")[:100], str(d.get("detail") or "")[:4000],
                     str(d.get("host") or ""), str(d.get("ctid") or ""), str(d.get("check") or ""),
                     json.dumps(d.get("probe")) if isinstance(d.get("probe"), dict) else None,
                     ctx,
                     "queued", secrets.token_urlsafe(16), now))
    c.commit(); i = cur.lastrowid; c.close()
    threading.Thread(target=handle, args=(i,), daemon=True).start()
    return i


def incident_link(inc_id):
    return "%s/incidents#%d" % (PUBLIC_BASE, inc_id)


STYLE = (":root{--blue:#1b75bc;--orange:#f7941e;--ink:#1d2733;--muted:#6b7785;--ground:#f4f6f8;--panel:#fff;--line:#dde3e9;"
         "--ok:#178a5b;--ok-bg:#e3f5ec;--warn:#9a6b00;--warn-bg:#fff3d6;--bad:#b3261e;--bad-bg:#fbe4e2;--idle:#5d6b78;--idle-bg:#edf0f3}"
         "*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,'Segoe UI',sans-serif;color:var(--ink);background:var(--ground)}"
         "a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}"
         ".top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 24px;background:var(--panel);"
         "border-bottom:3px solid var(--orange);flex-wrap:wrap}.top h1{margin:0;font-size:20px;color:var(--blue)}"
         "main{max-width:980px;margin:0 auto;padding:20px 24px}.muted{color:var(--muted)}.small{font-size:12px}"
         ".panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px}"
         ".panel:target{border-color:var(--blue);box-shadow:0 0 0 2px rgba(27,117,188,.18)}"
         ".head{display:flex;justify-content:space-between;align-items:center;gap:12px}.head h2{margin:0;font-size:15px}"
         ".chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}"
         ".chip.ok{color:var(--ok);background:var(--ok-bg)}.chip.warn{color:var(--warn);background:var(--warn-bg)}"
         ".chip.bad{color:var(--bad);background:var(--bad-bg)}.chip.idle,.chip.info{color:var(--idle);background:var(--idle-bg)}"
         "p{margin:8px 0 0}.k{font-size:12px;color:var(--muted);margin-top:10px}"
         "pre{white-space:pre-wrap;word-break:break-word;background:var(--ground);border:1px solid var(--line);border-radius:6px;"
         "padding:8px 10px;margin:8px 0 0;font:12px/1.5 ui-monospace,Consolas,monospace}"
         "label{display:block;font-size:12px;color:var(--muted);margin:10px 0 3px}"
         "input{width:100%;font:inherit;padding:8px 10px;border:1px solid #bfc8d1;border-radius:6px}"
         "button{font:inherit;padding:9px 16px;border:0;border-radius:6px;background:var(--blue);color:#fff;cursor:pointer;margin-top:14px}"
         "button.bad{background:var(--bad)}.err{color:var(--bad);font-size:13px;margin-top:10px}"
         "footer{text-align:center;font-size:11px;opacity:.6;padding:8px 0 24px}footer a{color:inherit}"
         "@media(max-width:700px){main{padding:16px}.top{padding:12px 16px}}")
FOOTER = "<footer>Medicine Man · built by <a href='https://www.sandz.co.za' target=_blank rel=noopener>SANDZ</a></footer>"


def shell(title, body, sub=""):
    return ("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width, initial-scale=1'>"
            "<title>%s · Healer</title><style>%s</style><header class=top><div><h1>%s</h1><div class='muted small'>%s</div></div>"
            "</header><main>%s</main>%s</html>" % (html.escape(title), STYLE, html.escape(title), sub, body, FOOTER))


def login_html(err="", nxt="/incidents"):
    return shell("Healer", "<form class=panel method=post action=/login style='max-width:380px;margin:0 auto'>"
                 "<input type=hidden name=next value='%s'><label>User</label><input name=user autocomplete=username autofocus>"
                 "<label>Password</label><input name=pass type=password autocomplete=current-password>"
                 "<button>Sign in</button>%s</form>" % (html.escape(nxt), ("<div class=err>%s</div>" % html.escape(err)) if err else ""),
                 "Sign in to see incidents")


def confirm_html(inc, action, tok):
    plan = json.loads(inc["plan"] or "{}")
    verb = "Approve and run" if action == "approve" else "Reject"
    return shell("Incident #%d" % inc["id"],
                 "<section class=panel><div class=head><h2>%s</h2></div><pre>%s</pre>"
                 "<form method=post action='/%s/%d'><input type=hidden name=t value='%s'>"
                 "<button class='%s'>%s</button></form></section>"
                 % (html.escape(inc["label"]), html.escape(fmt_plan(plan)), action, inc["id"], html.escape(tok),
                    "" if action == "approve" else "bad", verb),
                 "Nothing runs until you press the button")


INCIDENT_CHIP = {"healed": ("ok", "Healed"), "fix-failed": ("bad", "Fix failed"), "awaiting-approval": ("warn", "Needs your OK"),
                 "applied": ("info", "Applied, not verified"), "error": ("bad", "Healer error"), "diagnosed": ("info", "Diagnosed"), "rejected": ("idle", "Rejected"),
                 "queued": ("idle", "Queued"), "diagnosing": ("idle", "Diagnosing"), "applying": ("idle", "Applying")}


def page():
    c = db()
    rows = c.execute("SELECT id, ts, label, status, diagnosis, plan, result FROM incidents ORDER BY id DESC LIMIT 50").fetchall()
    c.close()
    items, counts = [], {}
    for r in rows:
        plan = json.loads(r[5] or "{}")
        cls, word = INCIDENT_CHIP.get(r[3], ("idle", r[3]))
        counts[word] = counts.get(word, 0) + 1
        items.append("<section class=panel id='%d'><div class=head><h2>#%d · %s</h2><span class='chip %s'>%s</span></div>"
                     "<div class='muted small'>%s</div>%s<pre>%s</pre>%s</section>" % (
            r[0], r[0], html.escape(r[2]), cls, html.escape(word), time.strftime("%d %b %H:%M", time.localtime(r[1])),
            ("<p><b>%s</b></p>" % html.escape(plan["root_cause"])) if plan.get("root_cause") else "",
            html.escape(fmt_plan(plan) if plan else (r[4] or "")),
            ("<div class=k>Result</div><pre>%s</pre>" % html.escape(r[6])) if r[6] else ""))
    summary = " · ".join("%d %s" % (n, w.lower()) for w, n in sorted(counts.items(), key=lambda x: -x[1])) or "no incidents"
    return shell("Incidents", "".join(items) or "<section class=panel><span class=muted>No incidents yet.</span></section>",
                 "Self-heal agent · never starts guests you shut down · last %d: %s · <a href='/logout'>Sign out</a>"
                 % (len(rows), html.escape(summary)))


LOGIN_FAILS = {}   # ip -> (count, first_ts); simple brute-force throttle


class H(BaseHTTPRequestHandler):
    def _s(self, code, body, ctype="application/json", headers=()):
        b = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("X-Frame-Options", "DENY"); self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")      # approve/view tokens never leak via Referer
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _cookie(self, value, age):
        return ("Set-Cookie", "healer_v=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax%s"
                % (value, age, "; Secure" if PUBLIC_BASE.startswith("https") else ""))

    def _jar(self):
        return dict(p.strip().split("=", 1) for p in (self.headers.get("Cookie") or "").split(";") if "=" in p)

    def _tok_ok(self):
        return bool(TOKEN) and same(self.headers.get("X-Healer-Token", ""), TOKEN)

    def _body(self, limit=65536):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if 0 < n <= limit else b""

    def _client(self):
        if TRUST_PROXY and self.headers.get("X-Forwarded-For"):
            # The LAST entry is the one your proxy appended; anything before it the client wrote itself.
            return self.headers["X-Forwarded-For"].split(",")[-1].strip()
        return self.client_address[0]

    def _decision(self, m, tok):
        """(incident, error-response) for an approve/reject link."""
        c = db(); inc = get_incident(c, int(m.group(2))); c.close()
        if not inc or not tok or not same(inc["token"], tok):
            return None, (403, "bad link")
        if inc["status"] != "awaiting-approval":
            return None, (409, "already %s" % inc["status"])
        return inc, None

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); qs = urllib.parse.parse_qs(u.query)
        if u.path == "/health":
            return self._s(200, {"ok": True, "claude_auth": bool(env("CLAUDE_CODE_OAUTH_TOKEN") or env("ANTHROPIC_API_KEY"))
                                 or os.path.isfile("/home/%s/.claude/.credentials.json" % AI_USER), "hosts": len(HOSTS)})
        if u.path == "/":
            return self._s(302, "", "text/plain", (("Location", "/incidents"),))
        if u.path == "/incidents":
            if not VIEW_TOKEN:
                return self._s(503, "Set HEALER_VIEW_TOKEN to enable the incident page.", "text/plain")
            v = (qs.get("v") or [""])[0]
            if v and same(v, VIEW_TOKEN):
                # Set the cookie, then drop the key from the address bar (and from browser history).
                return self._s(302, "", "text/plain", (("Location", "/incidents"), self._cookie(VIEW_TOKEN, 31536000)))
            if same(self._jar().get("healer_v", ""), VIEW_TOKEN):
                return self._s(200, page(), "text/html; charset=utf-8")
            if WEB_PASS:
                return self._s(302, "", "text/plain", (("Location", "/login"),))
            return self._s(401, "Sign-in not configured (set HEALER_WEB_PASS) - open the page with ?v=<view key>.", "text/plain")
        if u.path == "/login":
            if not (WEB_PASS and VIEW_TOKEN):
                return self._s(503, "Login not configured (set HEALER_WEB_PASS and HEALER_VIEW_TOKEN).", "text/plain")
            return self._s(200, login_html(), "text/html; charset=utf-8")
        if u.path == "/logout":
            return self._s(302, "", "text/plain", (("Location", "/login"), self._cookie("", 0)))
        m = re.fullmatch(r"/(approve|reject)/(\d+)", u.path)
        if m:
            # GET only shows the plan: link scanners in mail clients open links, so nothing may run on GET.
            tok = (qs.get("t") or [""])[0]
            inc, err = self._decision(m, tok)
            if err:
                return self._s(err[0], err[1], "text/plain")
            return self._s(200, confirm_html(inc, m.group(1), tok), "text/html; charset=utf-8")
        self._s(404, {"error": "not found"})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path); qs = urllib.parse.parse_qs(u.query)
        m = re.fullmatch(r"/(approve|reject)/(\d+)", u.path)
        if m:
            form = urllib.parse.parse_qs(self._body(4096).decode("utf-8", "replace"))
            inc, err = self._decision(m, (form.get("t") or [""])[0])
            if err:
                return self._s(err[0], err[1], "text/plain")
            # Claim the incident atomically: of two clicks (or two tabs) only one moves it out of
            # awaiting-approval, so a plan can never run twice.
            c = db()
            new = "rejected" if m.group(1) == "reject" else "applying"
            won = c.execute("UPDATE incidents SET status=?, updated=? WHERE id=? AND status='awaiting-approval'",
                            (new, int(time.time()), inc["id"])).rowcount == 1
            c.commit(); c.close()
            if not won:
                return self._s(409, "already handled", "text/plain")
            if new == "rejected":
                return self._s(200, shell("Rejected", "<section class=panel>Nothing was run.</section>"), "text/html; charset=utf-8")
            threading.Thread(target=approve, args=(inc["id"],), daemon=True).start()
            return self._s(200, shell("Approved", "<section class=panel>Running now. The result arrives the same way as "
                                      "this alert, and on the <a href='/incidents#%d'>incident page</a>.</section>" % inc["id"]),
                           "text/html; charset=utf-8")
        if u.path == "/login":
            if not (WEB_PASS and VIEW_TOKEN):
                return self._s(503, "Login not configured.", "text/plain")
            ip = self._client()
            cnt, first = LOGIN_FAILS.get(ip, (0, time.time()))
            if time.time() - first > 900:
                cnt, first = 0, time.time()        # 15-min window
            if cnt >= 8:
                return self._s(429, login_html("Too many attempts - wait a few minutes."), "text/html; charset=utf-8")
            form = urllib.parse.parse_qs(self._body(4096).decode("utf-8", "replace"))
            user = (form.get("user") or [""])[0]; pw = (form.get("pass") or [""])[0]
            if not (same(user, WEB_USER) and same(pw, WEB_PASS)):
                if len(LOGIN_FAILS) > 10000:
                    LOGIN_FAILS.clear()                # bounded memory under a spray of addresses
                LOGIN_FAILS[ip] = (cnt + 1, first)
                time.sleep(0.5)
                return self._s(401, login_html("Wrong user or password."), "text/html; charset=utf-8")
            LOGIN_FAILS.pop(ip, None)
            return self._s(302, "", "text/plain", (("Location", "/incidents"), self._cookie(VIEW_TOKEN, 31536000)))
        if not self._tok_ok():
            return self._s(403, {"error": "token"})
        if u.path == "/incident":
            try:
                d = json.loads(self._body() or b"{}")
            except ValueError:
                return self._s(400, {"error": "json"})
            if not d.get("key"):
                return self._s(400, {"error": "key required"})
            try:
                i = new_incident(d)
            except ValueError as e:
                return self._s(400, {"error": str(e)})
            return self._s(200, {"incident": i, "deduped": i is None})
        if u.path == "/diagnose":
            g = lambda k: (qs.get(k) or [""])[0]
            i = new_incident({"key": g("key") or ("manual#" + g("ip")), "label": g("label") or g("ip"), "ip": g("ip"),
                              "detail": g("detail") or "manual check"})
            return self._s(200, {"incident": i, "deduped": i is None})
        self._s(404, {"error": "not found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    db().close()
    print("healer on %s:%d, %d hosts" % (BIND, PORT, len(HOSTS)), flush=True)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
