"""seed an empty neo4j database with the sample organisation's network and alerts (requirement R1)."""
import json
import sys

from .db import ROOT, driver

SAMPLE = ROOT / "data" / "sample_org"
# every node in the attack graph also carries the label Entity, so analyses work across all kinds
NODE_LABELS = {"User", "Group", "Computer", "CloudResource", "ServiceIdentity", "AIAgent", "Tool", "Software", "Internet"}
EDGE_TYPES = {"MemberOf", "AdminTo", "CanRDP", "GenericAll", "HasSession",
              "LoggedInto", "RemoteLogon", "ConnectedTo",
              "ExposedTo", "Runs", "SyncedTo", "Owns", "RunsAs", "RoleOn", "CanEmail", "FeedsUntrustedInput",
              "CanPrompt", "HasToolAccess", "CanAccess", "InvokedTool"}
# the cloud tenant, ai agents and web server added to the sample organisation (see the file's description)
EXTENSIONS = [SAMPLE / "cloud_ai.json"]


def load(session, network_path=SAMPLE / "network.json", alerts_path=SAMPLE / "alerts.json"):
    load_network(session, network_path)
    alerts = json.loads(alerts_path.read_text())
    # new activity on the sample day: an edge seen for the first time keeps first_seen = time
    for event in alerts["events"]:
        _check_type(event["type"])
        session.run(
            f"""
            MATCH (s {{id: $src}}), (d {{id: $dst}})
            MERGE (s)-[r:{event['type']}]->(d)
            ON CREATE SET r.first_seen = $time, r.count = 0, r.family = 'observed', r.user = $user
            SET r.last_seen = $time, r.count = r.count + 1
            """,
            src=event["src"], dst=event["dst"], time=event["time"], user=event.get("user"),
        )

    for alert in alerts["alerts"]:
        props = {k: v for k, v in alert.items() if k not in ("involves", "scenario")}
        session.run("CREATE (a:Alert) SET a = $props, a.status = 'new'", props=props)
        for entity in alert["involves"]:
            session.run(
                "MATCH (a:Alert {id: $a}), (e {id: $e}) WHERE NOT e:Alert CREATE (a)-[:Involves]->(e)",
                a=alert["id"], e=entity,
            )
    return counts(session)


def load_network(session, network_path=SAMPLE / "network.json"):
    """wipe the database and load the network only: users, machines, groups, permissions and past activity.
    this is the starting point of the live replay, before any of the day's events arrive."""
    network = json.loads(network_path.read_text())
    if network_path == SAMPLE / "network.json":
        for ext in EXTENSIONS:
            if ext.exists():
                extra = json.loads(ext.read_text())
                for key in ("nodes", "granted", "observed"):
                    network[key] = network[key] + extra.get(key, [])
    load_network_data(session, network)
    # vulnerabilities for the software in the network, from the saved snapshot of the public sources
    from .vulns import refresh
    refresh(session, live=False)
    # real sources reporting from outside (an ai agent on a team laptop) are drawn back into the fresh graph
    from .sources import apply_all
    apply_all(session)


def load_network_data(session, network):
    """load a network given as a dict with nodes, granted and observed. used by load_network (from a file) and
    by the importers (from BloodHound or CSV), so every entry point builds the same graph the same way."""
    # records reported by real sources (sources.py) survive a reload and are drawn back in afterwards
    session.run("MATCH (n) WHERE NOT n:SourceRecord AND NOT n:SourceEvent DETACH DELETE n")
    for label in NODE_LABELS:
        session.run(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE")
    session.run("CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE")

    by_label = {}
    for node in network["nodes"]:
        if node["label"] not in NODE_LABELS:
            raise ValueError(f"unknown label {node['label']}")
        by_label.setdefault(node["label"], []).append({k: v for k, v in node.items() if k != "label"})
    for label, rows in by_label.items():
        session.run(f"UNWIND $rows AS props CREATE (n:{label}:Entity) SET n = props, "
                    "n.location = coalesce(props.location, 'onprem')", rows=rows)

    _edges(session, network["granted"], family="granted")
    _edges(session, network["observed"], family="observed")


def counts(session):
    return {
        "nodes": session.run("MATCH (n:Entity) RETURN count(n) AS c").single()["c"],
        "edges": session.run("MATCH ()-[r]->() WHERE type(r) IN $types RETURN count(r) AS c", types=list(EDGE_TYPES)).single()["c"],
        "alerts": session.run("MATCH (a:Alert) RETURN count(a) AS c").single()["c"],
    }


def _check_type(edge_type):
    if edge_type not in EDGE_TYPES:
        raise ValueError(f"unknown edge type {edge_type}")


def _edges(session, edges, family):
    """create edges with one query per edge type rather than one per edge."""
    by_type = {}
    for edge in edges:
        _check_type(edge["type"])
        props = {k: v for k, v in edge.items() if k not in ("src", "dst", "type")}
        props["family"] = family
        by_type.setdefault(edge["type"], []).append({"src": edge["src"], "dst": edge["dst"], "props": props})
    for edge_type, rows in by_type.items():
        session.run(
            f"UNWIND $rows AS row MATCH (s {{id: row.src}}), (d {{id: row.dst}}) CREATE (s)-[r:{edge_type}]->(d) SET r = row.props",
            rows=rows)


if __name__ == "__main__":
    with driver() as d, d.session() as s:
        counts = load(s)
        from .analysis import run_all
        run_all(s)
        from .scoring import score_all
        score_all(s)
    print(json.dumps(counts))
    sys.exit(0)
