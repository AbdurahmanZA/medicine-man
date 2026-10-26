#!/usr/bin/env python3
"""Runs healer-gate.py against attack-style commands. 1 = must ALLOW, 0 = must DENY.

  python3 gate/test_gate.py        (exit code 1 on any failure)
"""
import os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "healer-gate.py")

CASES = [
    # --- diagnosis that must keep working ---
    ("ro", "pct exec 101 -- systemctl status nginx", 1),
    ("ro", "journalctl -u myapp -n 50 --no-pager | grep -i error", 1),
    ("ro", "pct exec 102 -- sh -c 'tail -n 50 /var/log/syslog | grep err'", 1),
    ("ro", "zfs list -o name,used", 1),
    ("ro", "curl -s http://127.0.0.1:3000/health", 1),
    ("ro", "pct exec 101 -- curl -s -o /dev/null -w %{http_code} http://127.0.0.1/", 1),
    ("ro", "curl -fsS -m 5 -H 'Host: app.example.com' https://127.0.0.1/", 1),
    ("ro", "pct exec 103 -- pm2 ls", 1),
    ("ro", "pct list 2>/dev/null", 1),
    ("ro", "pct exec 101 -- cat /etc/nginx/sites-enabled/default", 1),
    ("ro", "pct exec 101 -- tailscale status", 1),
    ("ro", "pct exec 104 -- tailscale funnel status", 1),
    ("ro", "pct exec 101 -- tailscale serve status", 1),
    ("ro", "pct exec 101 -- cat /root/.ssh/authorized_keys", 1),
    ("ro", "pct exec 101 -- last -n 20", 1),
    ("ro", "cat /etc/passwd", 1),
    ("ro", "pct exec 105 -- asterisk -rx 'pjsip show registrations'", 1),
    ("ro", "pct exec 105 -- asterisk -rx 'core show channels' | grep -c active", 1),
    ("ro", "pct exec 105 -- docker ps -a", 1),
    ("ro", "ip -br addr", 1),
    ("ro", "ip route show", 1),
    ("ro", "find /var/log -name '*.log' -mmin -60", 1),
    ("ro", "systemctl --no-pager status nginx", 1),
    ("ro", "systemctl --failed", 1),
    ("ro", "ps -eo pid,etime,args", 1), ("ro", "ps aux", 1), ("ro", "ps axo pid,etime", 1),
    ("ro", "grep -rn error /var/log/nginx", 1), ("ro", "grep -H -r -v -E '^[[:space:]]*(#|$)' /etc/cron.d/", 1),
    ("ro", "curl -s -w %{http_code} -o /dev/null http://127.0.0.1/", 1),
    ("ro", "awk '{print $1}' /var/log/syslog | sort | uniq -c", 1),
    ("ro", "openssl x509 -in /etc/ssl/certs/app.pem -noout -enddate", 1),
    ("ro", "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", 1),
    ("ro", "top -b -n 1", 1),
    ("ro", "date", 1),
    ("ro", "hostname -I", 1),
    ("ro", "mount", 1),
    ("ro", "dmesg -T", 1),
    ("rw", "pct exec 101 -- systemctl restart nginx", 1),
    ("rw", "pct exec 103 -- pm2 restart myapp", 1),
    ("rw", "pct exec 105 -- docker restart frigate", 1),
    ("rw", "pct exec 101 -- systemctl restart cloudflared", 1),
    ("rw", "pct exec 101 -- systemctl restart tailscaled", 1),
    ("rw", "pct exec 101 -- systemctl reload nginx", 1),
    ("rw", "pct exec 104 -- tailscale funnel status", 1),

    # --- lifecycle: never, in either mode ---
    ("ro", "pct start 101", 0), ("rw", "pct start 101", 0), ("rw", "qm start 201", 0),
    ("rw", "pct set 101 --onboot 1", 0), ("rw", "pct exec 101 -- reboot", 0),
    ("rw", "systemctl stop pve-cluster && pct start 1", 0),

    # --- destructive ---
    ("rw", "pct exec 101 -- rm -rf /opt", 0), ("ro", "zfs destroy rpool/x", 0),
    ("rw", "pct exec 101 -- sqlite3 x.db 'DELETE FROM users'", 0),

    # --- ro must be read-only ---
    ("ro", "pct exec 101 -- systemctl restart nginx", 0),
    ("ro", "pct exec 102 -- sh -c 'df -h; rm -rf /tmp/x'", 0),
    ("ro", "pct exec 102 -- sh -c 'tail /var/log/syslog | tee /etc/x'", 0),
    ("ro", "ls|sh", 0), ("ro", "cat /etc/hosts > /tmp/x", 0), ("ro", "", 0),
    ("ro", "curl -s -X POST http://x", 0), ("ro", "curl -s -o /etc/x http://a", 0), ("ro", "curl -s http://a -o", 0),
    ("ro", "pm2 restart all", 0),
    ("ro", "pct exec 101 -- sqlite3 /opt/x.db 'select 1'", 0),
    ("ro", "pct exec 105 -- asterisk -rx 'core restart now'", 0),
    ("ro", "pct exec 105 -- asterisk -rx 'channel request hangup all'", 0),
    ("ro", "pct exec 105 -- asterisk -r", 0),
    ("ro", "pct exec 105 -- docker compose restart frigate", 0),
    ("ro", "pct exec 104 -- tailscale funnel reset", 0),
    # read-only bypasses closed in this release
    ("ro", "ls\ntouch /etc/x", 0),                                  # newline = second command
    ("ro", "env sh -c 'touch /etc/x'", 0),                          # env runs commands
    ("ro", "find / -name x -delete", 0), ("ro", "find /tmp -exec touch /etc/x ;", 0),
    ("ro", "awk 'BEGIN{system(\"touch /etc/x\")}'", 0),
    ("ro", "pct exec 101 -- sqlite3 -readonly x.db '.shell touch /etc/x'", 0),
    ("ro", "sqlite3 -readonly -cmd '.system id' x.db", 0),
    ("ro", "sort -o /etc/hosts /tmp/x", 0), ("ro", "uniq /tmp/a /etc/hosts", 0),
    ("ro", "curl -s -D /etc/x http://a", 0), ("ro", "curl -s -K /tmp/cfg http://a", 0),
    ("ro", "curl -s file:///etc/hostname", 0),
    ("ro", "ip addr add 10.0.0.9/24 dev eth0", 0), ("ro", "ip route del default", 0),
    ("ro", "hostname evil", 0), ("ro", "date -s 2001-01-01", 0), ("ro", "mount /dev/sdb1 /mnt", 0),
    ("ro", "dmesg -C", 0), ("ro", "ss -K dst 10.0.0.1", 0), ("ro", "smartctl -t long /dev/sda", 0),
    ("ro", "openssl genrsa -out /tmp/k 2048", 0), ("ro", "ssh-keygen -t ed25519 -f /tmp/k", 0),
    ("ro", "journalctl --vacuum-size=1M", 0), ("ro", "timedatectl set-time 2001-01-01", 0),
    ("ro", "systemd-analyze set-log-level debug", 0),
    # 2026-10-27 review: bypasses found by an independent review, all must be refused
    ("ro", "echo .shell id | sqlite3 -readonly /x.db", 0),
    ("ro", "sqlite3 -readonly x.db \"select writefile('/tmp/x','y')\"", 0),
    ("ro", "pct exec 101 -- sqlite3 -readonly /opt/x.db 'select 1'", 0),
    ("ro", "systemctl --no-pager restart example.service", 0), ("ro", "systemctl -q stop example", 0),
    ("ro", "/var/lib/vz/example/cat /x", 0), ("ro", "pct exec 101 -- /tmp/cat /etc/hosts", 0),
    ("ro", "echo link show | ip -b -", 0), ("ro", "sort --compress-program=/bin/true /x", 0),
    ("ro", "smartctl --set=standby,now /dev/sda", 0), ("ro", "awk -i inplace 1 /etc/hosts", 0),
    ("ro", "awk -f /tmp/prog.awk /x", 0), ("ro", "awk '@load \"x\"' /x", 0),
    ("ro", "cat /etc/sha?ow", 0), ("ro", "cat /etc/sh{a,}dow", 0), ("ro", "cat /etc//shadow", 0),
    ("ro", "cat /etc/./shadow", 0), ("ro", "cat /etc/x/../shadow", 0), ("ro", "cat /etc/sh''adow", 0),
    ("ro", "cat ~root/.ssh/authorized_keys", 0), ("ro", "cat $HOME/x", 0), ("ro", r"cat /etc/shdow", 0), ("ro", "cat /etc/shdow", 0),
    ("ro", "grep -r token /etc/pve", 0), ("ro", "grep -rn key /opt/app", 0), ("ro", "ps auxe", 0), ("ro", "ps eww", 0),
    ("ro", "pct exec 103 -- pm2 jlist", 0), ("ro", "pm2 describe 0", 0),
    ("ro", "curl -s -H @/etc/hosts http://a", 0), ("ro", "curl -s -w @/etc/hosts http://a", 0),
    ("ro", "date -f /etc/hosts", 0), ("ro", "sha256sum -c /etc/hosts", 0), ("ro", "dig -f /etc/hosts", 0),
    ("ro", "sh -c 'cat $0' /etc/shadow", 0), ("ro", "nginx -s stop", 0),
    # guests must not stop through a side door, in either mode
    ("rw", "pct exec 101 -- systemctl restart kexec.target", 0), ("rw", "pct exec 101 -- systemctl start exit.target", 0),
    ("rw", "pct exec 101 -- systemctl --no-block reboot", 0), ("rw", "systemctl start pve-container@101", 0),
    ("rw", "systemctl stop qemu-server@201", 0), ("rw", "lxc-stop -n 101", 0), ("rw", "pct exec 101 -- kill 1", 0),
    ("rw", "pct exec 101 -- pkill -f nginx", 0), ("rw", "pct exec 101 -- systemctl kill nginx", 0),
    # secrets never leave the host
    ("ro", "cat /etc/shadow", 0), ("ro", "pct exec 101 -- cat /opt/app/.env", 0),
    ("ro", "cat /root/.ssh/id_ed25519", 0), ("ro", "cat /proc/1/environ", 0),
    ("ro", "pct exec 105 -- docker inspect frigate", 0), ("ro", "getent shadow root", 0),
    ("ro", "ls /etc/pve/priv", 0), ("ro", "cat /etc/ssl/private/privkey.pem", 0),

    # --- exposure lock: nothing may become public ---
    ("rw", "pct exec 103 -- tailscale funnel 443 on", 0), ("rw", "pct exec 103 -- tailscale serve --bg 80", 0),
    ("rw", "pct exec 104 -- tailscale funnel status && tailscale funnel 443 on", 0),
    ("rw", "pct exec 104 -- tailscale serve status --json", 0),
    ("rw", "pct exec 101 -- cloudflared tunnel route dns x y", 0), ("rw", "pct exec 101 -- ufw allow 80", 0),
    ("rw", "pct exec 101 -- iptables -I INPUT -j ACCEPT", 0),
    ("rw", "iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to 1.2.3.4", 0),
    ("rw", "pct exec 101 -- sed -i s/a/b/ /etc/nginx/sites-enabled/x", 0),
    ("rw", "pct exec 101 -- cp /tmp/x /etc/cloudflared/config.yml", 0),
    ("rw", "pvesh set /nodes/pve1/lxc/101/firewall/options --enable 0", 0),
    ("rw", "pct exec 101 -- socat TCP-LISTEN:80 x", 0), ("rw", "pct exec 103 -- ssh -R 80:localhost:80 x", 0),

    # --- accounts ---
    ("rw", "pct exec 101 -- sed -i /x/d /root/.ssh/authorized_keys", 0), ("rw", "pct exec 101 -- useradd evil", 0),
    ("rw", "pct exec 101 -- cp x /etc/sudoers", 0), ("rw", "passwd root", 0), ("rw", "pct exec 101 -- passwd root", 0),

    ("xx", "ls", 0),                                                # unknown mode
]

# Site extensions from the config dir
EXTRA = [("ro", "my-appcheck 101", 1), ("ro", "my-appcheck 101; id", 0), ("ro", "cat /srv/vault/x", 0),
         ("ro", "ls /etc/pve/lxc/*.conf", 1),                  # trusted verbatim via gate-ro-exact
         ("ro", "ls /etc/pve/lxc/*.conf ; id", 0), ("ro", "ls /etc/pve/qemu-server/*.conf", 0),
         ("rw", "ls /etc/pve/lxc/*.conf", 1)]


def run(mode, cmd, conf):
    env = {**os.environ, "SSH_ORIGINAL_COMMAND": cmd, "HEALER_GATE_DRYRUN": "1",
           "HEALER_GATE_LOG": os.devnull, "HEALER_GATE_CONF_DIR": conf}
    r = subprocess.run([sys.executable, GATE, mode], env=env, capture_output=True, text=True)
    return (1 if r.returncode == 0 else 0), r.stderr.strip()


def main():
    bad = 0
    with tempfile.TemporaryDirectory() as empty, tempfile.TemporaryDirectory() as conf:
        with open(os.path.join(conf, "gate-ro-extra"), "w") as f:
            f.write("# site check scripts\nmy-appcheck\n")
        with open(os.path.join(conf, "gate-deny-read"), "w") as f:
            f.write("/srv/vault\n")
        with open(os.path.join(conf, "gate-ro-exact"), "w") as f:
            f.write("# fixed monitoring sweeps\nls /etc/pve/lxc/*.conf\n")
        for cases, d in ((CASES, empty), (EXTRA, conf)):
            for mode, cmd, want in cases:
                got, err = run(mode, cmd, d)
                if got != want:
                    bad += 1
                    print("BAD %s %s %r | %s" % (mode, "ALLOW" if got else "DENY", cmd, err[:100]))
    total = len(CASES) + len(EXTRA)
    print("cases: %d  failures: %d" % (total, bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
