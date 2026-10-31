"""real sources that report into GraphOps from outside: team laptops running osquery (kind endpoint) and AI agents
such as Claude Code on a team laptop (kind ai_agent).

a source sends, with the shared ingest token (X-GraphOps-Token, env INGEST_TOKEN):
- an inventory. a laptop: local accounts and which are admins, who is signed in, listening ports, disk encryption and
  firewall (collectors/osquery/collect.py). an agent: what it CAN reach, its folders, secret files by name only and
  which services their keys are for, accounts it is signed in to and tools it can call (collectors/claude_code/scan.py).
- events. a laptop: what changed since the last report (a new admin, a new port, someone signing in), each one an
  alert in triage, scored like every other alert. an agent: what it DID, one event per tool call with no contents
  (collectors/claude_code/hook.py), drawn as UsedAccess edges.

both are stored on SourceRecord / SourceEvent nodes, which loading a scenario does not wipe, and drawn into the graph
after every load, so a real laptop or agent sits in the same graph, explorer and triage as everything else."""
import datetime as dt
import hmac
import json
import os

from .attack import ATTACK_EDGES

MAX_EVENTS = 500  # newest events kept per source
ACTIVITY_DAYS = 7  # for an agent, "used" means used within this many days
KINDS = {"endpoint", "ai_agent"}

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


def _kind(session, source_id):
    r = session.run("MATCH (s:SourceRecord {id: $id}) RETURN s.kind AS k", id=source_id).single()
    return r and r["k"]


def save_events(session, source_id, events):
    """store a source's events. returns (stored, alerts): alerts is true when they became triage alerts, so the
    caller re-runs the analysis. an agent's events are only drawn as used-access edges, which is cheap."""
    if _kind(session, source_id) == "ai_agent" or any(e.get("target") for e in events[:1]):
        return _save_agent_events(session, source_id, events), False
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
    _trim(session, source_id)
    _draw_alerts(session, source_id)
    return len(rows), bool(rows)


def _save_agent_events(session, source_id, events):
    rows = []
    for e in events[:200]:
        target = str(e.get("target") or "")[:200]
        if not target:
            continue
        rows.append({"time": str(e.get("time") or _now())[:32], "tool": str(e.get("tool") or "")[:60],
                     "target": target, "detail": str(e.get("detail") or "")[:120]})
    session.run(
        """
        MERGE (s:SourceRecord {id: $id}) SET s.last_seen = $now
        WITH s UNWIND $rows AS row
        CREATE (:SourceEvent {source: $id, time: row.time, tool: row.tool, target: row.target, detail: row.detail})
        """, id=source_id, rows=rows, now=_now())
    _trim(session, source_id)
    _draw_used(session, source_id)
    return len(rows)


def _trim(session, source_id):
    session.run("MATCH (e:SourceEvent {source: $id}) WITH e ORDER BY e.time DESC SKIP $keep DELETE e",
                id=source_id, keep=MAX_EVENTS)


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
    if rec["kind"] == "ai_agent":
        _draw_agent(session, source_id, json.loads(rec["inv"]))
        _draw_used(session, source_id)
    else:
        _draw_endpoint(session, source_id, json.loads(rec["inv"]))
        _draw_alerts(session, source_id)


def _host_id(inv):
    return inv["host"]


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
        MERGE (n:User:Entity {id: u.name + '@' + $hid})
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
    rec = session.run("MATCH (s:SourceRecord {id: $id}) RETURN s.kind AS kind, s.inventory AS inv", id=source_id).single()
    if not rec or not rec["inv"] or rec["kind"] != "endpoint":
        return
    hid = _host_id(json.loads(rec["inv"]))
    rows = []
    # one alert per kind of change and subject, the newest: a collector restarted with no memory reports the same
    # weak settings again, and that is not a new change
    latest = {}
    for e in session.run("MATCH (e:SourceEvent {source: $id}) RETURN e.time AS time, e.kind AS kind, e.subject AS subject, "
                         "e.detail AS detail ORDER BY e.time", id=source_id):
        latest[(e["kind"], e["subject"])] = e
    for e in latest.values():
        spec = EVENT_ALERTS[e["kind"]]
        aid = f"rl-{source_id}-{e['kind']}-{e['time']}"[:120]
        involves = [hid] + ([f"{e['subject']}@{hid}"] if e["kind"] in ("admin_added", "user_signed_in") and e["subject"] else [])
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


def _draw_agent(session, source_id, inv):
    agent = inv["agent"]
    aid = agent["id"]
    # remove this source's previous drawing, then draw the current inventory
    session.run("MATCH (n:Entity {source: $sid}) DETACH DELETE n", sid=source_id)
    nodes = [{"id": aid, "label": "AIAgent", "name": agent.get("name", aid), "location": "onprem",
              "platform": agent.get("platform"), "host": agent.get("host"), "mode": agent.get("mode"),
              "allow": agent.get("allow", [])[:50], "deny": agent.get("deny", [])[:50], "real": True}]
    nodes += [{"id": f["id"], "label": "Folder", "name": f.get("name", f["id"]), "path": f.get("path"),
               "location": "onprem"} for f in inv.get("folders", [])]
    nodes += [{"id": s["id"], "label": "Secret", "name": s.get("name", s["id"]), "path": s.get("path"),
               "location": "onprem"} for s in inv.get("secrets", [])]
    nodes += [{"id": s["id"], "label": "CloudResource", "name": s.get("name", s["id"]), "location": "cloud",
               "resourcetype": s.get("type", "service"), "critical": bool(s.get("critical"))}
              for s in inv.get("services", [])]
    nodes += [{"id": t["id"], "label": "Tool", "name": t.get("name", t["id"]), "location": "onprem",
               "kind": "mcp_server" if t.get("mcp") else "built_in"} for t in inv.get("tools", [])]
    for label in {n["label"] for n in nodes}:
        rows = [{k: v for k, v in n.items() if k != "label"} for n in nodes if n["label"] == label]
        # MERGE so a service already in the graph (for example the internet) is reused, not duplicated
        session.run(f"UNWIND $rows AS props MERGE (n:{label}:Entity {{id: props.id}}) "
                    "SET n += props, n.source = $sid", rows=rows, sid=source_id)

    edges = [{"src": aid, "type": "CanRead", "dst": f["id"]} for f in inv.get("folders", [])]
    for s in inv.get("secrets", []):
        edges.append({"src": s["folder"], "type": "Contains", "dst": s["id"]})
        edges += [{"src": s["id"], "type": "HoldsKeyFor", "dst": svc} for svc in s.get("services", [])]
    edges += [{"src": aid, "type": "SignedInTo", "dst": a["service"], "account": a.get("account")}
              for a in inv.get("accounts", [])]
    edges += [{"src": aid, "type": "HasToolAccess", "dst": t["id"]} for t in inv.get("tools", [])]
    session.run("MERGE (i:Internet:Entity {id: 'internet'}) ON CREATE SET i.name = 'The internet', "
                "i.location = 'external'")
    # a tool that reads the open web (a browser, web fetch) lets any page put instructions in front of the agent
    edges += [{"src": "internet", "type": "FeedsUntrustedInput", "dst": aid, "via": t["id"]}
              for t in inv.get("tools", []) if t.get("untrusted_input")]
    for etype in {e["type"] for e in edges}:
        session.run(
            f"""
            UNWIND $rows AS row
            MATCH (a:Entity {{id: row.src}}), (b:Entity {{id: row.dst}})
            MERGE (a)-[r:{etype}]->(b)
            SET r.family = 'granted', r.source = $sid, r.account = row.account, r.via = row.via
            """, rows=[e for e in edges if e["type"] == etype], sid=source_id)


def _draw_used(session, source_id):
    """one UsedAccess edge from the agent to each thing its recent tool calls touched, with a count."""
    rec = session.run("MATCH (s:SourceRecord {id: $id}) RETURN s.inventory AS inv", id=source_id).single()
    if not rec or not rec["inv"] or "agent" not in json.loads(rec["inv"]):
        return
    aid = json.loads(rec["inv"])["agent"]["id"]
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=ACTIVITY_DAYS)).isoformat(timespec="seconds")
    session.run("MATCH (:AIAgent {id: $aid})-[r:UsedAccess]->() DELETE r", aid=aid)
    session.run(
        """
        MATCH (e:SourceEvent {source: $sid}) WHERE e.time >= $since
        WITH e.target AS target, count(*) AS n, max(e.time) AS last
        MATCH (a:AIAgent {id: $aid}), (t:Entity {id: target})
        MERGE (a)-[r:UsedAccess]->(t)
        SET r.count = n, r.last_seen = last, r.family = 'observed'
        """, sid=source_id, aid=aid, since=since)


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


def agent_view(session, source_id):
    """everything the AI agents tab shows for one agent: what it can reach, what it used, its live activity and
    the shortest route from the open web through it to a critical service."""
    rec = session.run("MATCH (s:SourceRecord {id: $id}) RETURN s.inventory AS inv, s.last_seen AS last_seen, "
                      "s.inventory_at AS inventory_at", id=source_id).single()
    if not rec or not rec["inv"]:
        return None
    inv = json.loads(rec["inv"])
    aid = inv["agent"]["id"]
    reach = session.run(
        f"""
        MATCH (a:AIAgent {{id: $aid}})-[g:CanRead|SignedInTo|HasToolAccess]->(x)
        OPTIONAL MATCH (x)-[:Contains]->(sec)-[:HoldsKeyFor]->(svc)
        WITH a, g, x, collect(DISTINCT {{secret: sec.id, service: svc.id}}) AS keys
        OPTIONAL MATCH (a)-[u:UsedAccess]->(x)
        RETURN x.id AS id, x.name AS name, [l IN labels(x) WHERE l <> 'Entity'][0] AS kind, type(g) AS how,
               coalesce(x.critical, false) AS critical, coalesce(u.count, 0) AS used, u.last_seen AS last_used,
               [k IN keys WHERE k.secret IS NOT NULL] AS keys
        ORDER BY how, id
        """, aid=aid).data()
    secrets = session.run(
        """
        MATCH (a:AIAgent {id: $aid})-[:CanRead]->(f)-[:Contains]->(s:Secret)
        OPTIONAL MATCH (s)-[:HoldsKeyFor]->(svc)
        OPTIONAL MATCH (a)-[u:UsedAccess]->(s)
        RETURN s.id AS id, s.name AS name, f.id AS folder, collect(DISTINCT svc.name) AS services,
               coalesce(u.count, 0) AS used
        ORDER BY id
        """, aid=aid).data()
    services = session.run(
        """
        MATCH (a:AIAgent {id: $aid})
        MATCH (svc:CloudResource {source: $sid})
        OPTIONAL MATCH direct = (a)-[:SignedInTo]->(svc)
        OPTIONAL MATCH via = (a)-[:CanRead]->()-[:Contains]->()-[:HoldsKeyFor]->(svc)
        OPTIONAL MATCH (a)-[u:UsedAccess]->(svc)
        RETURN svc.id AS id, svc.name AS name, coalesce(svc.critical, false) AS critical,
               direct IS NOT NULL AS signed_in, via IS NOT NULL AS via_secret, coalesce(u.count, 0) AS used
        ORDER BY critical DESC, id
        """, aid=aid, sid=source_id).data()
    rel = "|".join(ATTACK_EDGES)
    # for each critical service this agent can reach, the shortest route from the open web through the agent
    paths = session.run(
        f"""
        MATCH (i:Internet {{id: 'internet'}}), (a:AIAgent {{id: $aid}})
        MATCH (c:CloudResource {{source: $sid, critical: true}})
        MATCH p = shortestPath((i)-[:{rel}*..8]->(c))
        WHERE a IN nodes(p)
        RETURN c.id AS target, c.name AS target_name, [n IN nodes(p) | n.id] AS nodes,
               [r IN relationships(p) | type(r)] AS types
        ORDER BY length(p) DESC, target
        """, aid=aid, sid=source_id).data()
    events = session.run(
        "MATCH (e:SourceEvent {source: $sid}) RETURN e.time AS time, e.tool AS tool, e.target AS target, "
        "e.detail AS detail ORDER BY e.time DESC LIMIT 40", sid=source_id).data()
    # all past sessions, from the agent's own logs (sent with the access scan): how often each thing was touched
    hist = inv.get("history") or {}
    ever = hist.get("targets", {})
    for row in reach + secrets + services:
        row["ever"] = ever.get(row["id"], {}).get("count", 0)
    used = sum(1 for r in reach if r["used"]) + sum(1 for s in secrets if s["used"])
    granted = len(reach) + len(secrets)
    return {
        "source": source_id, "agent": inv["agent"], "last_seen": rec["last_seen"], "inventory_at": rec["inventory_at"],
        "reach": reach, "secrets": secrets, "services": services, "events": events,
        "summary": {"folders": len(inv.get("folders", [])), "secrets": len(secrets), "services": len(services),
                    "critical_services": sum(1 for s in services if s["critical"]), "tools": len(inv.get("tools", [])),
                    "granted": granted, "used": used, "days": ACTIVITY_DAYS},
        "attack_paths": paths,
        "history": {k: hist.get(k) for k in ("sessions", "tool_calls", "first", "last", "notable")} if hist else None,
        "aws_profiles": inv.get("aws_profiles"),
    }
