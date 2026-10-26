"""Per-app playbooks for component incidents.

An incident that carries {"ctid": "...", "check": "..."} (and "host") is matched against
$HEALER_PLAYBOOKS (default /etc/healer/playbooks.json):

  {"<ctid>": {"_app":  "what runs in this guest, ports, how to re-run the checks",
              "_host": "the Proxmox host name (from the hosts file) the guest lives on",
              "<check>": {"means": "what the failing check says",
                          "look":  ["read-only things to check first (must pass healer-gate ro)"],
                          "fix":   ["the ONLY commands that may auto-run, exactly as run on the host"],
                          "note":  "conditions / when to propose no fix"}}}

A playbook incident auto-applies only when every proposed command is in its "fix" list, runs on
"_host", AND passes healer.is_safe(). Anything else goes to the approve link. An empty "fix"
means never auto-fix (report only). See examples/playbooks.example.json.
"""
import json, os

PATH = os.environ.get("HEALER_PLAYBOOKS", "/etc/healer/playbooks.json")


def load():
    try:
        with open(PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def for_incident(inc):
    """(ctid, check, host, app-intro, playbook) for an app component incident, else None."""
    ctid, check = str(inc.get("ctid") or ""), inc.get("check") or ""
    if not (ctid and check):
        return None
    book = load().get(ctid, {})
    if check not in book or check.startswith("_"):
        return None
    return ctid, check, book.get("_host") or inc.get("host") or "", book.get("_app", ""), book[check]
