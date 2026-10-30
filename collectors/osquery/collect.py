"""endpoint collector: reads this laptop with osquery and reports to GraphOps.

every minute it asks osquery (https://osquery.io, the open-source endpoint agent many companies run across their
fleets) a few questions: which local accounts exist and which are admins, who is signed in, which network ports are
listening and by which program, and whether disk encryption and the firewall are on. it sends that as an inventory
when anything changes, sends each change as an event (GraphOps turns it into an alert), and otherwise a heartbeat.

names and settings only: no files, no browsing, no command lines, no network addresses. account names are replaced
by stable labels unless "mask_users" is false in the config.

config, kept on this laptop: ~/.graphops/endpoint.json
    {"url": "https://graph-ops.vercel.app", "token": "...", "source": "laptop-vatanesh", "label": "Vatanesh's laptop",
     "owner": "Vatanesh", "mask_users": true}
usage: python3 collect.py            (runs until stopped; Ctrl+C)
       python3 collect.py --once     (one report, then exit)
       python3 collect.py --dry-run  (print what would be sent)"""
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

CONFIG = Path.home() / ".graphops" / "endpoint.json"
STATE = Path.home() / ".graphops" / "endpoint-state.json"
EVERY = 60
OSQUERYI = [shutil.which("osqueryi"), "/usr/local/bin/osqueryi", "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd",
            r"C:\Program Files\osquery\osqueryi.exe"]

QUERIES = {
    "system": "SELECT hostname, computer_name FROM system_info",
    "os": "SELECT name, version, platform FROM os_version",
    "version": "SELECT version FROM osquery_info",
    "users": "SELECT username, uid FROM users",
    "admins": "SELECT DISTINCT u.username FROM users u JOIN user_groups ug ON u.uid = ug.uid JOIN groups g ON g.gid = ug.gid "
              "WHERE g.groupname IN ('admin', 'Administrators', 'sudo', 'wheel')",
    "signed_in": "SELECT DISTINCT user FROM logged_in_users",
    "listening": "SELECT DISTINCT lp.port, p.name FROM listening_ports lp JOIN processes p ON lp.pid = p.pid "
                 "WHERE lp.port > 0 AND lp.protocol = 6 AND lp.address NOT IN ('127.0.0.1', '::1')",
    "mac_firewall": "SELECT global_state FROM alf",
    "win_security": "SELECT firewall FROM windows_security_center",
    "encryption": "SELECT encrypted FROM disk_encryption",
    "bitlocker": "SELECT protection_status FROM bitlocker_info",
}


def osqueryi():
    for p in OSQUERYI:
        if p and Path(p).exists():
            return [p, "-S"] if p.endswith("osqueryd") else [p]
    sys.exit("osquery is not installed: see collectors/osquery/README.md")


def ask(sql):
    try:
        out = subprocess.run(osqueryi() + ["--json", sql], capture_output=True, text=True, timeout=60).stdout
        return json.loads(out or "[]")
    except (ValueError, subprocess.TimeoutExpired, OSError):
        return []


def is_person(u):
    """real people's accounts, not the dozens of system accounts every os ships with."""
    name, uid = u.get("username", ""), int(u.get("uid") or 0)
    if name.startswith("_") or name in ("root", "daemon", "nobody", "Guest", "DefaultAccount", "WDAGUtilityAccount"):
        return False
    return uid >= 500 if platform.system() != "Windows" else True


def snapshot(cfg):
    q = {k: ask(v) for k, v in QUERIES.items()}
    mask = cfg.get("mask_users", True)
    label = lambda n: ("user-" + hashlib.sha256(n.encode()).hexdigest()[:4]) if mask else n
    admins = {r["username"] for r in q["admins"]}
    signed = {r["user"] for r in q["signed_in"]}
    users = [{"name": label(u["username"]), "admin": u["username"] in admins, "signed_in": u["username"] in signed}
             for u in q["users"] if is_person(u)]
    fw = None
    if q["mac_firewall"]:
        fw = q["mac_firewall"][0].get("global_state") not in ("0", 0, None)
    elif q["win_security"]:
        fw = q["win_security"][0].get("firewall") == "Good"
    enc = None
    if q["encryption"]:
        enc = any(r.get("encrypted") in ("1", 1) for r in q["encryption"])
    if q["bitlocker"]:
        enc = any(r.get("protection_status") in ("1", 1) for r in q["bitlocker"])
    os_row = (q["os"] or [{}])[0]
    return {
        "host": cfg["source"], "label": cfg.get("label") or cfg["source"], "owner": cfg.get("owner"),
        "os": f"{os_row.get('name', '')} {os_row.get('version', '')}".strip() or platform.platform(),
        "osquery_version": (q["version"] or [{}])[0].get("version"),
        "users": sorted(users, key=lambda u: u["name"]),
        "listening": sorted({(int(r["port"]), r["name"]) for r in q["listening"]}),
        "firewall": fw, "disk_encrypted": enc,
    }


def changes(prev, now):
    """what changed since the last report, as events. the first report flags settings that are already weak."""
    t = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    ev = []
    before = {u["name"]: u for u in (prev or {}).get("users", [])}
    for u in now["users"]:
        if u["admin"] and not before.get(u["name"], {}).get("admin") and prev is not None:
            ev.append({"time": t, "kind": "admin_added", "subject": u["name"], "detail": "account is now in the admin group"})
        if u["signed_in"] and not before.get(u["name"], {}).get("signed_in"):
            ev.append({"time": t, "kind": "user_signed_in", "subject": u["name"], "detail": "signed in"})
    old_ports = {tuple(p) for p in (prev or {}).get("listening", [])}
    for port, proc in now["listening"]:
        if prev is not None and (port, proc) not in old_ports:
            ev.append({"time": t, "kind": "port_opened", "subject": f"{port}/{proc}", "detail": f"{proc} listens on port {port}"})
    if now["firewall"] is False and (prev is None or prev.get("firewall") is not False):
        ev.append({"time": t, "kind": "firewall_off", "subject": "", "detail": "the host firewall is off"})
    if now["disk_encrypted"] is False and (prev is None or prev.get("disk_encrypted") is not False):
        ev.append({"time": t, "kind": "encryption_off", "subject": "", "detail": "the system disk is not encrypted"})
    return ev


def post(cfg, path, body):
    req = urllib.request.Request(cfg["url"].rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-GraphOps-Token": cfg["token"],
                                          "User-Agent": "graphops-osquery"})
    with urllib.request.urlopen(req, timeout=120) as res:
        return json.loads(res.read())


def report(cfg, dry=False):
    prev = json.loads(STATE.read_text()) if STATE.exists() else None
    now = snapshot(cfg)
    now["listening"] = [list(p) for p in now["listening"]]
    ev = changes(prev, now)
    if dry:
        print(json.dumps({"inventory": now, "events": ev}, indent=1))
        return
    src = cfg["source"]
    if now != prev:
        post(cfg, f"/api/sources/{src}/inventory", {"kind": "endpoint", "inventory": now})
    post(cfg, f"/api/sources/{src}/events", {"events": ev})
    STATE.write_text(json.dumps(now))
    print(f"{dt.datetime.now():%H:%M:%S} reported: {len(now['users'])} accounts, {len(now['listening'])} listening ports, "
          f"{len(ev)} change(s)")


if __name__ == "__main__":
    cfg = json.loads(CONFIG.read_text())
    if "--dry-run" in sys.argv:
        report(cfg, dry=True)
    elif "--once" in sys.argv:
        report(cfg)
    else:
        while True:
            try:
                report(cfg)
            except Exception as exc:  # keep running through a dropped connection or a server restart
                print(f"report failed: {exc}")
            time.sleep(EVERY)
