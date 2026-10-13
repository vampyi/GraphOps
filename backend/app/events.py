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
    first = tx.run(
        """
        MERGE (e:Event {id: $id})
        ON CREATE SET e.time = $time, e.kind = $kind, e.source_tool = $tool, e.new = true
        ON MATCH SET e.new = false
        RETURN e.new AS new
        """,
        id=event["event_id"], time=event["time"], kind=event["kind"], tool=event["source_tool"],
    ).single()["new"]
    if not first:
        return "skipped"
    return _HANDLERS[event["kind"]](tx, event)


def _observed_edge(tx, edge_type, src, dst, time, user=None):
    """create or update an observed edge. returns True when the edge is new."""
    row = tx.run(
        f"""
        MATCH (s {{id: $src}}), (d {{id: $dst}}) WHERE NOT s:Alert AND NOT d:Alert
        MERGE (s)-[r:{edge_type}]->(d)
        ON CREATE SET r.first_seen = $time, r.last_seen = $time, r.count = 0, r.family = 'observed',
                      r.user = $user, r.created = true
        ON MATCH SET r.created = false
        SET r.count = r.count + 1,
            r.last_seen = CASE WHEN $time > r.last_seen THEN $time ELSE r.last_seen END
        WITH r, r.created AS created
        REMOVE r.created
        RETURN created
        """,
        src=src, dst=dst, time=time, user=user,
    ).single()
    if row is None:
        log.warning("%s %s -> %s: unknown entity, skipped", edge_type, src, dst)
        return False
    return row["created"]


def _logon(tx, e):
    created = _observed_edge(tx, e["kind"], e["src"], e["dst"], e["time"], e.get("user"))
    return "network" if created and e["kind"] in ATTACK_EDGES else "activity"


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
    return "network"


def _process(tx, e):
    tx.run(
        "MATCH (ev:Event {id: $id}) SET ev.host = $host, ev.user = $user, ev.process = $process, ev.parent = $parent",
        id=e["event_id"], host=e["host"], user=e.get("user"), process=e["process"], parent=e.get("parent"))
    return "activity"


def _connection(tx, e):
    _observed_edge(tx, "ConnectedTo", e["src"], e["dst"], e["time"])
    return "activity"


def _alert(tx, e):
    props = {k: e.get(k) for k in ("id", "time", "name", "severity", "tactic_id", "technique_id", "source_tool")}
    tx.run("MERGE (a:Alert {id: $id}) ON CREATE SET a += $props, a.status = 'new'", id=e["id"], props=props)
    for entity in e["involves"]:
        tx.run(
            "MATCH (a:Alert {id: $a}), (x {id: $x}) WHERE NOT x:Alert AND NOT x:Event MERGE (a)-[:Involves]->(x)",
            a=e["id"], x=entity)
    return "alert"


def _asset(tx, e):
    props = {k: e[k] for k in ASSET_FIELDS if k in e}
    row = tx.run(
        f"""
        OPTIONAL MATCH (old:{e['label']} {{id: $id}})
        WITH old.critical AS was
        MERGE (n:{e['label']} {{id: $id}})
        SET n += $props
        RETURN was, n.critical AS now
        """,
        id=e["id"], props=props).single()
    return "network" if bool(row["was"]) != bool(row["now"]) else "activity"


_HANDLERS = {
    "LoggedInto": _logon, "RemoteLogon": _logon, "MemberOf": _member_of, "ProcessStart": _process,
    "Connection": _connection, "Alert": _alert, "Asset": _asset,
}
