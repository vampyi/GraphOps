"""seed an empty neo4j database with the sample organisation's network and alerts (requirement R1)."""
import json
import sys

from .db import ROOT, driver

SAMPLE = ROOT / "data" / "sample_org"
NODE_LABELS = {"User", "Group", "Computer"}
EDGE_TYPES = {"MemberOf", "AdminTo", "CanRDP", "GenericAll", "HasSession",
              "LoggedInto", "RemoteLogon", "ConnectedTo"}


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
    session.run("MATCH (n) DETACH DELETE n")
    for label in NODE_LABELS:
        session.run(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE")
    session.run("CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE")

    by_label = {}
    for node in network["nodes"]:
        if node["label"] not in NODE_LABELS:
            raise ValueError(f"unknown label {node['label']}")
        by_label.setdefault(node["label"], []).append({k: v for k, v in node.items() if k != "label"})
    for label, rows in by_label.items():
        session.run(f"UNWIND $rows AS props CREATE (n:{label}) SET n = props", rows=rows)

    _edges(session, network["granted"], family="granted")
    _edges(session, network["observed"], family="observed")


def counts(session):
    return {
        "nodes": session.run("MATCH (n) WHERE n:User OR n:Group OR n:Computer RETURN count(n) AS c").single()["c"],
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
