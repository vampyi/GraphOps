"""turn streamed events into graph changes. every event is written at most once, keyed on its event_id."""
import json
import logging

from .analysis import ATTACK_EDGES
from .seed import NODE_LABELS

log = logging.getLogger("graphops.events")

TOPICS = ("identity", "edr", "flows", "alerts", "cmdb")
MAX_BYTES = 64 * 1024
COMMON = ("event_id", "time", "source_tool", "kind")

# fields each kind of event must carry, and the topic it belongs to
KINDS = {
    "LoggedInto": ("identity", ("src", "dst")),
    "RemoteLogon": ("identity", ("src", "dst", "user")),
    "MemberOf": ("identity", ("src", "dst", "change")),
    "ProcessStart": ("edr", ("host", "process")),
    "Connection": ("flows", ("src", "dst")),
    "Alert": ("alerts", ("id", "name", "severity", "involves")),
    "Asset": ("cmdb", ("id", "label")),
}
ASSET_FIELDS = ("name", "os", "zone", "owner", "critical")


class BadEvent(ValueError):
    pass


def parse(raw, topic):
    """check one message and return it as a dict. raises BadEvent for anything we cannot use."""
    if not raw:
        raise BadEvent("empty message")
    if len(raw) > MAX_BYTES:
        raise BadEvent(f"message larger than {MAX_BYTES} bytes")
    try:
        event = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BadEvent(f"not json: {exc}") from None
    if not isinstance(event, dict):
        raise BadEvent("not a json object")
    missing = [f for f in COMMON if not event.get(f)]
    if missing:
        raise BadEvent(f"missing {', '.join(missing)}")
    kind = event["kind"]
    if kind not in KINDS:
        raise BadEvent(f"unknown kind {kind}")
    expected_topic, fields = KINDS[kind]
    if topic != expected_topic:
        raise BadEvent(f"{kind} does not belong on topic {topic}")
    missing = [f for f in fields if event.get(f) in (None, "", [])]
    if missing:
        raise BadEvent(f"{kind} missing {', '.join(missing)}")
    if kind == "MemberOf" and event["change"] not in ("added", "removed"):
        raise BadEvent("change must be 'added' or 'removed'")
    if kind == "Asset" and event["label"] not in NODE_LABELS:
        raise BadEvent(f"unknown label {event['label']}")
    if kind == "Alert" and not isinstance(event["involves"], list):
        raise BadEvent("involves must be a list")
    return event


def apply(tx, event):
    """write one event inside a transaction. returns what changed: 'skipped', 'alert', 'network' or 'activity'."""
    r = apply_batch(tx, [event])
    if r["skipped"]:
        return "skipped"
    return "alert" if r["alerts"] else "network" if r["network"] else "activity"


def apply_batch(tx, events):
    """write many events inside one transaction with a few queries per kind of event, not one per event.
    this matters on the hosted site, where every query is a round trip over the internet to neo4j aura.
    returns counts: new events, duplicates skipped, alerts written and whether the network changed."""
    seen = {r["id"] for r in tx.run("UNWIND $ids AS id MATCH (e:Event {id: id}) RETURN e.id AS id",
                                    ids=[e["event_id"] for e in events])}
    fresh = []
    for e in events:
        if e["event_id"] not in seen:
            seen.add(e["event_id"])
            fresh.append(e)
    result = {"events": len(fresh), "skipped": len(events) - len(fresh), "alerts": 0, "network": False}
    if not fresh:
        return result
    tx.run(
        """
        UNWIND $rows AS row
        CREATE (e:Event {id: row.event_id})
        SET e.time = row.time, e.kind = row.kind, e.source_tool = row.source_tool,
            e.host = row.host, e.user = row.user, e.process = row.process, e.parent = row.parent
        """,
        rows=fresh)
    by_kind = {}
    for e in fresh:
        by_kind.setdefault(e["kind"], []).append(e)

    # inventory first, so later events in the batch can refer to a machine it adds
    for label in NODE_LABELS:
        rows = [e for e in by_kind.get("Asset", []) if e["label"] == label]
        if rows:
            changed = tx.run(
                f"""
                UNWIND $rows AS row
                OPTIONAL MATCH (old:{label} {{id: row.id}})
                WITH row, old.critical AS was
                MERGE (n:{label} {{id: row.id}})
                SET n += row.props
                RETURN sum(CASE WHEN coalesce(was, false) <> coalesce(n.critical, false) THEN 1 ELSE 0 END) AS c
                """,
                rows=[{"id": e["id"], "props": {k: e[k] for k in ASSET_FIELDS if k in e}} for e in rows]).single()["c"]
            result["network"] |= changed > 0

    for e in by_kind.get("MemberOf", []):
        _member_of(tx, e)
        result["network"] = True

    edges = {"LoggedInto": by_kind.get("LoggedInto", []), "RemoteLogon": by_kind.get("RemoteLogon", []),
             "ConnectedTo": by_kind.get("Connection", [])}
    for edge_type, rows in edges.items():
        if rows:
            created = _observed_edges(tx, edge_type, rows)
            result["network"] |= created > 0 and edge_type in ATTACK_EDGES

    alerts = by_kind.get("Alert", [])
    if alerts:
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (a:Alert {id: row.id}) ON CREATE SET a += row.props, a.status = 'new'
            WITH a, row
            UNWIND row.involves AS x
            MATCH (e {id: x}) WHERE NOT e:Alert AND NOT e:Event
            MERGE (a)-[:Involves]->(e)
            """,
            rows=[{"id": e["id"], "involves": e["involves"],
                   "props": {k: e.get(k) for k in ("id", "time", "name", "severity", "tactic_id", "technique_id", "source_tool")}}
                  for e in alerts])
        result["alerts"] = len(alerts)
    return result


def _observed_edges(tx, edge_type, events):
    """create or update observed edges for many events. returns how many edges are new."""
    rows = [{"src": e["src"], "dst": e["dst"], "time": e["time"], "user": e.get("user")} for e in events]
    r = tx.run(
        f"""
        UNWIND $rows AS row
        MATCH (s {{id: row.src}}), (d {{id: row.dst}})
        WHERE NOT s:Alert AND NOT s:Event AND NOT d:Alert AND NOT d:Event
        OPTIONAL MATCH (s)-[old:{edge_type}]->(d)
        WITH row, s, d, old IS NULL AS is_new
        MERGE (s)-[r:{edge_type}]->(d)
        ON CREATE SET r.first_seen = row.time, r.last_seen = row.time, r.count = 0, r.family = 'observed', r.user = row.user
        SET r.count = r.count + 1,
            r.first_seen = CASE WHEN row.time < r.first_seen THEN row.time ELSE r.first_seen END,
            r.last_seen = CASE WHEN row.time > r.last_seen THEN row.time ELSE r.last_seen END
        RETURN count(*) AS written, count(DISTINCT CASE WHEN is_new THEN r END) AS created
        """,
        rows=rows).single()
    if r["written"] < len(rows):
        log.warning("%s: %d events name an unknown user or machine and were skipped", edge_type, len(rows) - r["written"])
    return r["created"]


def _member_of(tx, e):
    if e["change"] == "added":
        tx.run(
            """
            MATCH (s {id: $src}), (g:Group {id: $dst})
            MERGE (s)-[r:MemberOf]->(g) ON CREATE SET r.family = 'granted', r.since = $time
            """,
            src=e["src"], dst=e["dst"], time=e["time"])
    else:
        tx.run("MATCH ({id: $src})-[r:MemberOf]->(:Group {id: $dst}) DELETE r", src=e["src"], dst=e["dst"])
