"""real sources that report into GraphOps from outside: today, team laptops running osquery (endpoint kind).

a source sends, with the shared ingest token (X-GraphOps-Token, env INGEST_TOKEN):
- an inventory: what the machine is and what is on it right now (collectors/osquery/collect.py): local accounts and
  which are admins, who is signed in, listening ports, disk encryption and firewall. names and settings only.
- events: what changed since the last report (a new admin account, a new listening port, someone signing in). each
  change becomes an alert in triage, scored like every other alert.

both are stored on SourceRecord / SourceEvent nodes, which loading a scenario does not wipe, and drawn into the graph
after every load, so a real laptop sits in the same graph, explorer and triage as everything else."""
import datetime as dt
import hmac
import json
import os

MAX_EVENTS = 500
KINDS = {"endpoint"}

# the change events a collector may report, and the alert each one raises
EVENT_ALERTS = {
    "admin_added":    {"name": "New local administrator account", "severity": "high", "tactic_id": "TA0003", "technique_id": "T1136.001"},
    "port_opened":    {"name": "New listening network port", "severity": "medium", "tactic_id": "TA0011", "technique_id": "T1571"},
    "user_signed_in": {"name": "User signed in", "severity": "low", "tactic_id": "TA0001", "technique_id": "T1078"},
    # attack.mitre.org, checked 30 oct 2026: T1686 sits under the newer tactic TA0112 Defense Impairment
    "firewall_off":   {"name": "Firewall turned off", "severity": "high", "tactic_id": "TA0112", "technique_id": "T1686"},
    # a weak setting, not an attack step, so it carries no technique
    "encryption_off": {"name": "Disk encryption is off", "severity": "medium", "tactic_id": None, "technique_id": None},
}


def check_token(given):
    """true when the request carries the ingest token set on this server. no token set means ingest is closed."""
    expected = os.environ.get("INGEST_TOKEN")
    return bool(expected) and bool(given) and hmac.compare_digest(given, expected)


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def save_inventory(session, source_id, kind, inventory):
    session.run(
        "MERGE (s:SourceRecord {id: $id}) SET s.kind = $kind, s.inventory = $inv, s.inventory_at = $now, s.last_seen = $now",
        id=source_id, kind=kind, inv=json.dumps(inventory), now=_now())
    apply_one(session, source_id)


def save_events(session, source_id, events):
    rows = []
    for e in events[:100]:
        kind = str(e.get("kind") or "")
        if kind not in EVENT_ALERTS:
            continue
        rows.append({"time": str(e.get("time") or _now())[:32], "kind": kind,
                     "subject": str(e.get("subject") or "")[:120], "detail": str(e.get("detail") or "")[:160]})
    session.run(
        """
        MERGE (s:SourceRecord {id: $id}) SET s.last_seen = $now
        WITH s UNWIND $rows AS row
        CREATE (:SourceEvent {source: $id, time: row.time, kind: row.kind, subject: row.subject, detail: row.detail})
        """, id=source_id, rows=rows, now=_now())
    session.run("MATCH (e:SourceEvent {source: $id}) WITH e ORDER BY e.time DESC SKIP $keep DELETE e",
                id=source_id, keep=MAX_EVENTS)
    _draw_alerts(session, source_id)
    return len(rows)


def heartbeat(session, source_id):
    session.run("MATCH (s:SourceRecord {id: $id}) SET s.last_seen = $now", id=source_id, now=_now())


def apply_all(session):
    """draw every stored source back into the graph. called after a scenario or network load wiped the entities."""
    for r in session.run("MATCH (s:SourceRecord) WHERE s.inventory IS NOT NULL RETURN s.id AS id").data():
        apply_one(session, r["id"])


def apply_one(session, source_id):
    rec = session.run("MATCH (s:SourceRecord {id: $id}) RETURN s.kind AS kind, s.inventory AS inv", id=source_id).single()
    if not rec or not rec["inv"] or rec["kind"] not in KINDS:
        return
    _draw_endpoint(session, source_id, json.loads(rec["inv"]))
    _draw_alerts(session, source_id)


def _host_id(inv):
    return f"ep:{inv['host']}"


def _draw_endpoint(session, source_id, inv):
    hid = _host_id(inv)
    session.run("MATCH (n:Entity {source: $sid}) DETACH DELETE n", sid=source_id)
    session.run(
        """
        MERGE (c:Computer:Entity {id: $id})
        SET c.name = $name, c.location = 'onprem', c.source = $sid, c.real = true, c.os = $os, c.owner = $owner,
            c.zone = 'normal', c.critical = false, c.disk_encrypted = $enc, c.firewall = $fw,
            c.listening = $ports, c.osquery = $osquery
        """, id=hid, name=inv.get("label") or inv["host"], sid=source_id, os=inv.get("os"), owner=inv.get("owner"),
        enc=inv.get("disk_encrypted"), fw=inv.get("firewall"), osquery=inv.get("osquery_version"),
        ports=[f"{p[0]}/{p[1]}" for p in inv.get("listening", [])][:40])
    users = inv.get("users", [])
    session.run(
        """
        UNWIND $users AS u
        MERGE (n:User:Entity {id: $hid + '/' + u.name})
        SET n.name = u.name, n.location = 'onprem', n.source = $sid, n.real = true, n.admin = u.admin
        WITH n, u
        MATCH (c:Computer {id: $hid})
        FOREACH (_ IN CASE WHEN u.admin THEN [1] ELSE [] END |
          MERGE (n)-[r:AdminTo]->(c) SET r.family = 'granted', r.source = $sid)
        FOREACH (_ IN CASE WHEN u.signed_in THEN [1] ELSE [] END |
          MERGE (n)-[l:LoggedInto]->(c) SET l.family = 'observed', l.source = $sid, l.last_seen = $now
          MERGE (c)-[h:HasSession]->(n) SET h.family = 'observed', h.source = $sid)
        """, users=users, hid=hid, sid=source_id, now=_now())


def _draw_alerts(session, source_id):
    """each reported change is an alert on the machine, in the same shape as every other alert, so it is ranked by
    the graph and linked into incidents like the rest."""
    rec = session.run("MATCH (s:SourceRecord {id: $id}) RETURN s.inventory AS inv", id=source_id).single()
    if not rec or not rec["inv"]:
        return
    hid = _host_id(json.loads(rec["inv"]))
    rows = []
    for e in session.run("MATCH (e:SourceEvent {source: $id}) RETURN e.time AS time, e.kind AS kind, e.subject AS subject, "
                         "e.detail AS detail ORDER BY e.time", id=source_id):
        spec = EVENT_ALERTS[e["kind"]]
        aid = f"rl-{source_id}-{e['kind']}-{e['time']}"[:120]
        involves = [hid] + ([f"{hid}/{e['subject']}"] if e["kind"] in ("admin_added", "user_signed_in") and e["subject"] else [])
        rows.append({"id": aid, "time": e["time"][:19], "involves": involves,
                     "props": {**spec, "id": aid, "time": e["time"][:19], "source_tool": "osquery",
                               "name": f"{spec['name']}: {e['subject']}" if e["subject"] else spec["name"],
                               "detail": e["detail"], "real": True, "source": source_id}})
    session.run(
        """
        UNWIND $rows AS row
        MERGE (a:Alert {id: row.id})
        ON CREATE SET a = row.props, a.status = 'new'
        WITH a, row
        UNWIND row.involves AS eid
        MATCH (e:Entity {id: eid})
        MERGE (a)-[:Involves]->(e)
        """, rows=rows)


def list_sources(session):
    out = []
    for r in session.run("MATCH (s:SourceRecord) RETURN s.id AS id, s.kind AS kind, s.inventory AS inv, "
                         "s.last_seen AS last_seen ORDER BY s.last_seen DESC"):
        inv = json.loads(r["inv"]) if r["inv"] else {}
        out.append({"id": r["id"], "kind": r["kind"], "last_seen": r["last_seen"], "label": inv.get("label") or inv.get("host"),
                    "host": _host_id(inv) if inv.get("host") else None, "os": inv.get("os"),
                    "users": len(inv.get("users", [])), "admins": sum(1 for u in inv.get("users", []) if u.get("admin")),
                    "listening": len(inv.get("listening", [])), "disk_encrypted": inv.get("disk_encrypted"),
                    "firewall": inv.get("firewall"),
                    "events": session.run("MATCH (e:SourceEvent {source: $id}) RETURN count(e) AS n", id=r["id"]).single()["n"]})
    return out
