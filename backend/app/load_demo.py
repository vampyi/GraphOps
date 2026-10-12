"""load the demo company network and alerts into an empty neo4j database (requirement R1)."""
import json
import sys

from .db import ROOT, driver

DEMO = ROOT / "data" / "demo"
NODE_LABELS = {"User", "Group", "Computer"}
EDGE_TYPES = {"MemberOf", "AdminTo", "CanRDP", "GenericAll", "HasSession",
              "LoggedInto", "RemoteLogon", "ConnectedTo"}


def load(session, network_path=DEMO / "network.json", alerts_path=DEMO / "alerts.json"):
    network = json.loads(network_path.read_text())
    alerts = json.loads(alerts_path.read_text())

    session.run("MATCH (n) DETACH DELETE n")
    for label in NODE_LABELS:
        session.run(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE")
    session.run("CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE")

    for node in network["nodes"]:
        label = node["label"]
        if label not in NODE_LABELS:
            raise ValueError(f"unknown label {label}")
        props = {k: v for k, v in node.items() if k != "label"}
        session.run(f"CREATE (n:{label}) SET n = $props", props=props)

    for edge in network["granted"]:
        _edge(session, edge, family="granted")
    for edge in network["observed"]:
        _edge(session, edge, family="observed")

    # new activity on the demo day: an edge seen for the first time keeps first_seen = time
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
    return {
        "nodes": session.run("MATCH (n) WHERE NOT n:Alert RETURN count(n) AS c").single()["c"],
        "edges": session.run("MATCH ()-[r]->() WHERE NOT type(r) = 'Involves' RETURN count(r) AS c").single()["c"],
        "alerts": session.run("MATCH (a:Alert) RETURN count(a) AS c").single()["c"],
    }


def _check_type(edge_type):
    if edge_type not in EDGE_TYPES:
        raise ValueError(f"unknown edge type {edge_type}")


def _edge(session, edge, family):
    _check_type(edge["type"])
    props = {k: v for k, v in edge.items() if k not in ("src", "dst", "type")}
    props["family"] = family
    session.run(
        f"MATCH (s {{id: $src}}), (d {{id: $dst}}) CREATE (s)-[r:{edge['type']}]->(d) SET r = $props",
        src=edge["src"], dst=edge["dst"], props=props,
    )


if __name__ == "__main__":
    with driver() as d, d.session() as s:
        counts = load(s)
        from .analysis import run_all
        run_all(s)
        from .scoring import score_all
        score_all(s)
    print(json.dumps(counts))
    sys.exit(0)
