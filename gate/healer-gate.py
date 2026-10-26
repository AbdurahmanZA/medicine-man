#!/usr/bin/env python3
"""healer-gate - SSH forced command on every Proxmox host the healer may touch.

authorized_keys on each Proxmox host (/root/.ssh/authorized_keys or /etc/pve/priv/authorized_keys):
  command="/usr/local/bin/healer-gate ro",restrict ssh-ed25519 AAAA... healer-ro
  command="/usr/local/bin/healer-gate rw",restrict ssh-ed25519 AAAA... healer-rw

The AI only ever holds the RO key (diagnosis). The RW key belongs to the healer daemon, which
uses it to run a plan that was either auto-classified safe or approved by a human. Both keys
are filtered here, on the host, no matter what the model decides.

Rules enforced in BOTH modes:
  * no guest or host lifecycle at all (start/stop/reboot/destroy/onboot...). A guest that is
    down may have been shut down on purpose; a human decides.
  * exposure lock: nothing may become more public (no Tailscale Funnel/Serve, tunnel routes,
    firewall openings, proxy/tunnel config edits, reverse tunnels).
  * no destructive storage/data/account commands.
RO mode is an allow-list: every pipe segment must be a known read-only command with read-only
arguments, and secrets (keys, .env files, shadow, process environments) may not be read,
because everything the AI reads is sent to the model provider.

Optional local extensions (one entry per line, # comments allowed):
  /etc/healer/gate-ro-extra     extra read-only commands, e.g. your own check scripts
  /etc/healer/gate-deny-read    extra regexes for paths the AI must never read
"""
import os, posixpath, re, shlex, sys, time

LOG = os.environ.get("HEALER_GATE_LOG", "/var/log/healer-gate.log")
CONF = os.environ.get("HEALER_GATE_CONF_DIR", "/etc/healer")
MODE = sys.argv[1] if len(sys.argv) > 1 else "ro"
CMD = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()

DENY = [
    r"\b(pct|qm)(\s+-\S+)*\s+(start|stop|shutdown|reboot|resume|suspend|create|destroy|restore|rollback|set|"
    r"migrate|clone|template|unlock|move[-_]volume|move[-_]disk|resize|snapshot|delsnapshot|mount|unmount)\b",
    r"\bonboot\b", r"\bvzdump\b.*--remove", r"\bpvesm\s+(remove|free|set|add)\b",
    r"\b(reboot|poweroff|halt)\b", r"\bshutdown\b", r"\binit\s+[06]\b",
    # systemctl power verbs even behind flags (systemctl --no-block reboot), and any target change:
    # restarting kexec.target / exit.target / halt.target stops a guest just like a reboot does.
    r"\bsystemctl\b(\s+-\S+)*\s+(reboot|poweroff|halt|kexec|isolate|mask|exit|emergency|rescue|default|"
    r"suspend|hibernate|hybrid-sleep|suspend-then-hibernate|soft-reboot|kill|set-default)\b",
    r"\bsystemctl\b[^;&|]*\b(start|restart|try-restart|reload-or-restart|stop|enable|disable)\b[^;&|]*\.target\b",
    # the host-side units and tools behind every guest
    r"\b(pve-container|qemu-server)@", r"\blxc-(start|stop|destroy|freeze|unfreeze|execute|attach|create|copy|snapshot)\b",
    r"\b(kill|killall|pkill|skill|kexec)\b",
    r"\brm\s+-\w*r\w*\s+(/|/\*|~|/root|/etc|/opt|/var|/home|/srv)(\s|$)",
    r"\bmkfs", r"\bdd\s+if=", r"\bwipefs\b", r"\bsgdisk\b", r"\bfdisk\b", r"\bparted\b",
    r"\bzfs\s+(destroy|rollback|rename|promote)\b", r"\bzpool\s+(destroy|labelclear|remove|detach|offline|split|export)\b",
    r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", r"\bTRUNCATE\b", r"\bDELETE\s+FROM\b",
    r"\btailscale\s+(down|logout|up)\b", r"\biptables\s+-(F|X|P)\b", r"\bnft\s+flush\b",
    r"\bip\s+link\s+set\s+\S+\s+down\b", r"\bifdown\b",
    r"(^|[;&|]\s*|--\s+|sudo\s+)passwd\b", r"\bchpasswd\b", r"\buserdel\b", r"\busermod\b", r"\buseradd\b", r"\badduser\b",
    r"\bgpasswd\b", r"\bvisudo\b",
    r"\bchmod\s+-R\s+\d+\s+/(\s|$)", r"\bchown\s+-R\s+\S+\s+/(\s|$)",
    r"\bcrontab\s+-r\b", r"\bpveceph\b", r"\bpvecm\b", r"\bha-manager\b",
    r"\bcurl\b.*\|\s*(ba)?sh\b", r"\bwget\b.*\|\s*(ba)?sh\b",
    # exposure lock: restart what exists, never change what is public
    r"\btailscale\s+(serve|funnel)\b(?!\s+status\s*$)", r"\btailscale\s+(set|cert|login|switch)\b",
    r"\bcloudflared\b.*\b(tunnel\s+(route|create|delete|run|token)|service\s+(install|uninstall)|--url)\b",
    r"\bufw\s+(allow|disable|delete|reset|insert|route|default)\b",
    r"\biptables\s+(-t\s+\S+\s+)?-(A|I|D|R)\b", r"\bnft\s+(add|insert|delete|replace)\b",
    r"\bpvesh\s+(set|create|delete)\b", r"/etc/pve/firewall",
    r"\bsocat\b", r"\bngrok\b", r"\bssh\s+.*-R\s", r"\bfrpc?\b",
]

# rw-only: reading proxy/tunnel/account config is fine for diagnosis; writing it is not.
RW_DENY = [r"authorized_keys", r"/etc/(passwd|shadow|group|gshadow|sudoers)",
           r"(/etc/nginx|/etc/cloudflared|/root/\.cloudflared|/var/lib/tailscale|/etc/caddy|/etc/apache2|"
           r"/etc/haproxy|/etc/traefik|/etc/ufw|/etc/nftables|/etc/iptables|/etc/hosts\.allow)"]

# ro-only: secrets. Whatever the AI reads leaves the host (it goes to the model provider).
DENY_READ = [
    r"/etc/(shadow|gshadow)", r"/etc/pve/priv\b", r"/etc/ssl/private\b",
    r"\bid_(rsa|dsa|ecdsa|ed25519)(_sk)?\b(?!\.pub)", r"(^|[/\s'\"])\.env(\.[\w-]+)?\b",
    r"\.(key|p12|pfx|kdbx)\b", r"priv(ate)?[-_]?key", r"[-_.]key\.pem\b",
    r"/proc/(\d+|self|thread-self)/environ", r"\.(git-credentials|netrc|pgpass|my\.cnf)\b",
    r"\bcredentials(\.json)?\b", r"\.docker/config\.json", r"\bgetent\s+(shadow|gshadow)\b",
]

# sqlite3 is deliberately absent: its dot-commands and writefile()/readfile() can run commands and
# read secrets in ways an argument check can't see (e.g. `echo .shell id | sqlite3 -readonly x.db`).
RO_CMDS = {"journalctl", "df", "free", "uptime", "cat", "tail", "head", "grep", "egrep", "ls", "find",
           "stat", "ps", "du", "dmesg", "ss", "ip", "hostname", "date", "wc", "sort", "uniq", "awk", "cut",
           "tr", "uname", "lsblk", "mount", "findmnt", "id", "whoami", "printenv", "pvesm",
           "zfs", "zpool", "pveversion", "nginx", "pm2", "docker", "litestream", "curl", "ping",
           "getent", "nslookup", "dig", "last", "lastlog", "who", "w", "ssh-keygen",
           "sha256sum", "openssl", "tailscale", "top", "lsof", "netstat", "which", "file",
           "sensors", "smartctl", "iostat", "vmstat", "arp", "timedatectl", "systemd-analyze", "echo", "true"}
RO_SUB = {
    "systemctl": {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-timers", "cat", "show", "--failed"},
    "pct": {"status", "config", "list", "exec", "df"},
    "qm": {"status", "config", "list"},
    "zfs": {"list", "get"}, "zpool": {"status", "list", "iostat"},
    # pm2 jlist/describe/show/env print each app's full environment (API keys), like docker inspect
    "pvesm": {"status", "list"}, "pm2": {"list", "ls", "logs", "status"},
    "docker": {"ps", "logs", "stats", "images"},   # no `inspect`: it prints containers' env (secrets)
    "nginx": {"-t", "-T"},
    "tailscale": {"status", "ip", "ping", "netcheck"}, "litestream": {"generations", "snapshots", "wal", "databases"},
    "timedatectl": {"status", "show", "timesync-status", "show-timesync", "list-timezones"},
    "systemd-analyze": {"time", "blame", "critical-chain", "security", "verify", "calendar", "timespan", "timestamp"},
    "openssl": {"x509", "s_client", "version", "verify"},
}

# Flags that turn a "read" command into a writer or an executor.
BAD_FLAGS = {
    "find": {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"},
    "sort": {"-o", "--output", "--compress-program"},
    "ip": {"-b", "-batch", "-force", "-B"},                       # batch mode reads commands from stdin
    "awk": {"-i", "--include", "-l", "--load", "-E", "--exec", "-f", "--file"},   # gawk inplace edit / extensions / program files
    "date": {"-f", "--file", "-s", "--set"},                      # -f echoes each line of a file in its errors
    "sha256sum": {"-c", "--check"},
    "dig": {"-f", "-k"},
    "ping": {"-f"},
    "journalctl": {"--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush", "--sync",
                   "--relinquish-var", "--smart-relinquish-var", "--setup-keys", "--update-catalog"},
    "dmesg": {"-C", "-c", "-D", "-E", "-n", "--clear", "--read-clear", "--console-off", "--console-on", "--console-level"},
    "ss": {"-K", "--kill"},
    "sensors": {"-s", "--set"},
    "smartctl": {"-t", "--test", "-s", "--smart", "--set", "-o", "--offlineauto", "-S", "--saveauto", "-X", "--abort"},
    "arp": {"-d", "--delete", "-s", "--set", "-f", "--file"},
    "file": {"-C", "--compile"},
    "openssl": {"-out", "-keyout"},
}
# Recursive grep would read every .env and key under a directory, so it's only allowed in
# directories that hold logs and service definitions.
GREP_RECURSE_OK = ("/var/log", "/etc/cron.d", "/etc/systemd/system", "/run/systemd", "/etc/nginx/sites-enabled",
                   "/etc/nginx/conf.d")
CURL_FLAGS = {"-s", "-S", "-f", "-k", "-L", "-I", "-i", "-v", "--silent", "--show-error", "--fail", "--insecure",
              "--location", "--head", "--include", "--verbose", "-4", "-6"}
CURL_VALUE_FLAGS = {"-m", "--max-time", "--connect-timeout", "-w", "--write-out", "-H", "--header", "-o", "--output",
                    "--resolve", "-A", "--user-agent"}
IP_OBJECTS = {"a", "addr", "address", "r", "route", "l", "link", "n", "neigh", "neighbour", "rule", "maddr"}
IP_WRITES = {"add", "del", "delete", "change", "chg", "replace", "set", "flush", "append", "prepend", "save", "restore",
             "up", "down", "exec", "flush"}


def _lines(name):
    try:
        with open(os.path.join(CONF, name)) as f:
            return [x.strip() for x in f if x.strip() and not x.lstrip().startswith("#")]
    except OSError:
        return []


RO_CMDS |= set(_lines("gate-ro-extra"))
DENY_READ += _lines("gate-deny-read")
# Exact command strings your own monitoring sends (not the AI), trusted verbatim in ro mode even if
# they use globs or awk programs the generic checks refuse. Hard-deny and secret paths still apply.
RO_EXACT = set(_lines("gate-ro-exact"))


def log(decision, why=""):
    try:
        with open(LOG, "a") as f:
            f.write("%s %s %s %s :: %s\n" % (time.strftime("%F %T"), MODE, decision, why, CMD))
    except Exception:
        pass


def deny(why):
    log("DENY", why)
    sys.stderr.write("healer-gate: DENIED (%s)\n" % why)
    sys.exit(126)


def shell_expansion(cmd):
    """Why bash would expand this before running it (globs, braces, ~, $, backslashes), or ''.
    Expansion would let a secret path or a different command hide from the checks below, so in
    read-only mode only literal text is allowed outside single quotes."""
    outside, quote = [], None
    for ch in cmd:
        if quote == "'":
            if ch == "'":
                quote = None
            continue
        if quote == '"':
            if ch == '"':
                quote = None
            elif ch in "$`\\":
                return "shell expansion inside double quotes"
            continue
        if ch in "'\"":
            quote = ch
            continue
        outside.append(ch)
    text = "".join(outside)
    if re.search(r"[*?\[\]~$\\`]", text):
        return "shell expansion (glob, ~, $ or backslash) in ro mode"
    if re.search(r"\{[^}]*(,|\.\.)", text):
        return "brace expansion in ro mode"
    return ""


def normalize_paths(text):
    t = re.sub(r"/{2,}", "/", text)
    t = re.sub(r"/(\./)+", "/", t)
    prev = None
    while prev != t:
        prev, t = t, re.sub(r"/(?!\.\./)[^/\s]+/\.\./", "/", t)
    return t


def args_ok(c, t):
    """Per-command argument checks for read commands that can also write or execute."""
    a = t[1:]
    bad = BAD_FLAGS.get(c, set())
    for x in a:
        if x.split("=", 1)[0] in bad:
            return False, "%s %s writes or executes" % (c, x)
    if c == "curl":
        i = 0
        while i < len(a):
            x = a[i]
            if x in CURL_VALUE_FLAGS:
                if i + 1 >= len(a):
                    return False, "curl %s needs a value" % x
                if x in ("-o", "--output") and a[i + 1] != "/dev/null":
                    return False, "curl write"
                if a[i + 1].startswith("@"):            # -H @file / -w @file send a file's contents anywhere
                    return False, "curl %s @file reads a file" % x
                i += 2; continue
            if x.startswith("-"):
                if x not in CURL_FLAGS and not re.fullmatch(r"-[sSfkLIiv46]+", x):
                    return False, "curl flag %s not allowed" % x
            elif not re.match(r"https?://", x):
                return False, "curl: only http(s) URLs"
            i += 1
        return True, ""
    if c == "awk" and any(re.search(r"\bsystem\s*\(|getline|\||>|@", x) for x in a):
        return False, "awk program runs commands, writes or loads code"
    if c in ("grep", "egrep") and any(re.match(r"^-[^-]*[rR]", x) or x in ("--recursive", "--dereference-recursive")
                                      or x.startswith("--directories=recurse") for x in a):
        paths = [posixpath.normpath(x) for x in a if x.startswith("/")]
        if not paths or not all(any(p == ok or p.startswith(ok + "/") for ok in GREP_RECURSE_OK) for p in paths):
            return False, "recursive grep only under %s" % ", ".join(GREP_RECURSE_OK)
    if c == "ps":
        # BSD-style "e" (ps auxe, ps eww) prints every process's environment. Values of -o/-p/etc. are
        # format lists or ids, not options, so skip those.
        for prev, x in zip([""] + a, a):
            if prev in ("-o", "-O", "--format", "-p", "--pid", "-u", "-U", "-C", "-G", "-g", "-t", "--sort") or re.fullmatch(r"[a-zA-Z]*[oO]", prev):
                continue
            if re.fullmatch(r"[a-zA-Z]+", x) and "e" in x:
                return False, "ps e prints process environments (secrets)"
    if c == "uniq" and len([x for x in a if not x.startswith("-")]) > 1:
        return False, "uniq with an output file"
    if c in ("hostname", "mount") and any(not x.startswith("-") or x in ("-F", "--file", "-b", "--boot", "-a", "--all", "-o")
                                          for x in a):
        return False, "%s may only show" % c
    if c == "date" and any(x in ("-s", "--set") or x.startswith("--set=") for x in a):
        return False, "date may only show"
    if c == "ip":
        words = [x for x in a if not x.startswith("-")]
        if words and (words[0] not in IP_OBJECTS or set(words[1:]) & IP_WRITES):
            return False, "ip may only show"
    if c == "ssh-keygen" and not (a and a[0] in ("-l", "-lf", "-L", "-Lf") ):
        return False, "ssh-keygen: fingerprints only (-l)"
    if c == "top" and "-b" not in a:
        return False, "top needs -b (batch)"
    return True, ""


def ro_ok(cmd, depth=0):
    """Read-only check: every pipe segment must be an allow-listed read command with read-only args."""
    if depth > 3:
        return False, "nesting too deep"
    if re.search(r"[\n\r]", cmd):
        return False, "newline in command"
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", cmd):
        return False, "control character in command"
    plain = re.sub(r"\d?>\s*/dev/null|2>&1", "", cmd)
    why = shell_expansion(plain)
    if why:
        return False, why
    if re.search(r"(`|\$\(|;|&&|\|\||(?<![0-9])>|>>|\btee\b|\bsed\s+-i\b)", plain):
        return False, "write/chain metacharacter in ro mode"
    try:
        lx = shlex.shlex(plain, posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return False, "unparseable"
    if any(x in ("&", "<", "<<", "(", ")") for x in toks):
        return False, "shell operator in ro mode"
    segs, cur = [], []
    for x in toks:                      # split on unquoted pipes only
        if x == "|":
            segs.append(cur); cur = []
        else:
            cur.append(x)
    segs.append(cur)
    for t in segs:
        if not t:
            return False, "empty segment"
        if t[0] in ("sudo", "timeout", "nice"):
            t = t[1:] if t[0] != "timeout" else t[2:]
            if not t:
                return False, "empty after wrapper"
        if "/" in t[0]:
            # /some/dir/cat would pass a basename check, and a guest can plant a binary called "cat"
            # where the host can see it. Commands are found on PATH only.
            return False, "give the command name, not a path (%s)" % t[0][:40]
        c = t[0]
        if c in ("sh", "bash") and len(t) >= 3 and t[1] == "-c":
            ok, why = ro_ok(t[2], depth + 1)
            if not ok:
                return ok, why
            continue
        if c == "pct" and len(t) > 1 and t[1] == "exec":
            if "--" not in t:
                return False, "pct exec without --"
            inner = t[t.index("--") + 1:]
            if not inner:
                return False, "pct exec with no command"
            ok, why = ro_ok(inner[2] if inner[:2] in (["sh", "-c"], ["bash", "-c"]) and len(inner) > 2
                            else " ".join(shlex.quote(x) for x in inner), depth + 1)
            if not ok:
                return ok, why
            continue
        if c == "tailscale" and len(t) == 3 and t[1] in ("funnel", "serve") and t[2] == "status":
            continue                    # read-only view of what is exposed
        if c == "asterisk":             # CLI "show" views only
            if len(t) == 3 and t[1] == "-rx" and re.fullmatch(r"(pjsip|core|ari|http|module|sip|iax2)\s+show\s+[\w\s.\-/]+", t[2].strip()):
                continue
            return False, "asterisk: only -rx '<pjsip|core|ari|http|module> show ...'"
        if c in RO_SUB:
            if c == "nginx":
                if len(t) != 2 or t[1] not in RO_SUB[c]:
                    return False, "nginx: only -t or -T"
                continue
            # The verb is the first word that isn't a flag: "systemctl --no-pager restart x" is a restart.
            words = [x for x in t[1:] if not x.startswith("-")]
            if not words:
                if c == "systemctl" and "--failed" in t:
                    continue
                return False, "%s needs a read-only subcommand" % c
            if words[0] not in RO_SUB[c]:
                return False, "%s %s not read-only" % (c, words[0])
            ok, why = args_ok(c, t)
            if not ok:
                return ok, why
            continue
        if c not in RO_CMDS:
            return False, "%s not in read allowlist" % c
        ok, why = args_ok(c, t)
        if not ok:
            return ok, why
    return True, ""


def main():
    if not CMD:
        deny("no interactive shell")
    if MODE not in ("ro", "rw"):
        deny("bad mode")
    for rx in DENY:
        if re.search(rx, CMD, re.I):
            deny("hard-deny /%s/" % rx[:40])
    if MODE == "ro":
        # Check the paths as the shell will see them: quotes removed and //, /./ and /x/../ collapsed,
        # so "/etc//shadow", "/etc/./shadow" and /etc/sh''adow can't slip past.
        for text in (CMD, normalize_paths(CMD), normalize_paths(CMD.replace('"', "").replace("'", ""))):
            for rx in DENY_READ:
                if re.search(rx, text, re.I):
                    deny("secret path /%s/" % rx[:40])
        ok, why = (True, "") if CMD in RO_EXACT else ro_ok(CMD)
        if not ok:
            deny(why)
    else:
        for rx in RW_DENY:
            if re.search(rx, CMD, re.I):
                deny("exposure lock: no writes to account/proxy/tunnel/firewall config")
    log("ALLOW")
    if os.environ.get("HEALER_GATE_DRYRUN"):
        print("ALLOW"); sys.exit(0)
    os.execvp("bash", ["bash", "-c", CMD])


if __name__ == "__main__":
    main()
