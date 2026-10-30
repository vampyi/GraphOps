"""the Neo4j story, made explicit for the dashboard: which graph algorithm answers which SOC question, the one
query behind each panel, and a side-by-side of the same question in Cypher and in SQL.

every number here is read live from the graph, and every query shown is one GraphOps actually runs."""
import os
import time

from .attack import ATTACK_EDGES, TACTICS, TECHNIQUES

REL = "|".join(ATTACK_EDGES)

# the one query behind each view, shown in the ui so judges see that every answer is a single graph query.
CYPHER = {
    "blast_radius": {
        "question": "What can an attacker on this machine reach in 1, 2 and 3 hops?",
        "cypher": f"MATCH (a:Alert {{id:$id}})-[:Involves]->(start)\n"
                  f"MATCH p = (start)-[:{REL}*1..3]->(n)\n"
                  f"RETURN n.id, min(length(p)) AS hop ORDER BY hop",
        "why_graph": "One variable-length pattern walks 1 to 3 hops. In SQL this is a UNION of three different "
                     "multi-join queries.",
    },
    "attack_path": {
        "question": "What is the fastest route from this machine to a critical asset?",
        "cypher": f"MATCH (start {{id:$src}}), (c) WHERE c.critical\n"
                  f"MATCH p = shortestPath((start)-[:{REL}*..8]->(c))\n"
                  f"RETURN [n IN nodes(p)|n.id] AS path ORDER BY length(p) LIMIT 1",
        "why_graph": "shortestPath finds the route at any depth. SQL needs a separate self-join per hop and "
                     "cannot express 'any depth' in one query.",
    },
    "incident": {
        "question": "Which scattered alerts are really one attack?",
        "cypher": "// connected components over alerts that share an entity or a logon within a time window\n"
                  "MATCH (a:Alert)-[:Involves]->(e)<-[:Involves]-(b:Alert)\n"
                  "WHERE a <> b AND abs(duration.between(datetime(a.time), datetime(b.time)).minutes) <= 120\n"
                  "RETURN a.id, b.id",
        "why_graph": "Alert grouping is weakly-connected components, a one-line graph algorithm.",
    },
    "choke": {
        "question": "Which one node carries the most attack paths?",
        "cypher": "CALL gds.betweenness.stream('attack') YIELD nodeId, score\n"
                  "RETURN gds.util.asNode(nodeId).id AS node, score ORDER BY score DESC",
        "why_graph": "Betweenness centrality is built into Neo4j's Graph Data Science library.",
    },
    "access": {
        "question": "What is this identity entitled to reach, through nested groups?",
        "cypher": "MATCH (u {id:$id})-[:MemberOf*0..6]->(p)-[:AdminTo|CanRDP|GenericAll]->(c)\n"
                  "RETURN DISTINCT c.id",
        "why_graph": "Nested group membership is a variable-length walk. In SQL the depth is unknown in advance.",
    },
}


def algorithms(session):
    """the graph algorithms GraphOps runs, each mapped to the SOC question it answers, with a live number from
    the current graph. this is the 'why Neo4j' roster."""
    one = lambda q, **p: (session.run(q, **p).single() or {})

    paths = one(
        f"MATCH (s) WHERE s.zone = 'low_trust' AND NOT coalesce(s.critical,false) "
        f"MATCH (c) WHERE c.critical = true "
        f"MATCH p = shortestPath((s)-[:{REL}*..8]->(c)) RETURN count(p) AS n").get("n", 0)
    top_choke = one("MATCH (n) WHERE n.choke_score IS NOT NULL RETURN n.id AS id ORDER BY n.choke_score DESC LIMIT 1").get("id")
    top_danger = one("MATCH (n) WHERE n.danger IS NOT NULL RETURN n.id AS id ORDER BY n.danger DESC LIMIT 1").get("id")
    communities = one("MATCH (n) WHERE n.community IS NOT NULL RETURN count(DISTINCT n.community) AS n").get("n", 0)
    incidents = one("MATCH (i:Incident) RETURN count(i) AS n").get("n", 0)
    lateral = one("MATCH (i:Incident) WHERE i.lateral RETURN count(i) AS n").get("n", 0)
    reach = one(f"MATCH (s)-[:{REL}*1..3]->(c) WHERE c.critical AND s.zone='low_trust' RETURN count(DISTINCT s) AS n").get("n", 0)

    return [
        {"algorithm": "Variable-length traversal", "engine": "Cypher", "gds": False,
         "question": "What can a compromised host reach in N hops (blast radius)?",
         "result": f"{reach} low-trust machine{'s' if reach != 1 else ''} within 3 hops of a crown jewel"},
        {"algorithm": "Shortest path (Dijkstra)", "engine": "Cypher / GDS", "gds": False,
         "question": "What is the fastest attack route to a critical asset?",
         "result": f"{paths} shortest low-trust to critical paths mapped"},
        {"algorithm": "Betweenness centrality", "engine": "GDS", "gds": True,
         "question": "Which node is the biggest choke point?",
         "result": f"{top_choke or 'n/a'} carries the most paths"},
        {"algorithm": "PageRank", "engine": "GDS", "gds": True,
         "question": "Which node would cause the most disruption if compromised?",
         "result": f"{top_danger or 'n/a'} ranks most central"},
        {"algorithm": "Louvain community detection", "engine": "GDS", "gds": True,
         "question": "Which machines normally work together (so crossing groups looks like lateral movement)?",
         "result": f"{communities} activity communities found"},
        {"algorithm": "Connected components (WCC)", "engine": "GDS / Cypher", "gds": False,
         "question": "Which scattered alerts are one incident?",
         "result": f"{incidents} incidents, {lateral} crossing communities"},
        {"algorithm": "Max-flow / minimum cut", "engine": "GDS / networkx", "gds": False,
         "question": "What is the fewest permissions to cut every attack path?",
         "result": "see the Attack paths tab's top fix"},
    ]


def reachability_proof(session, src, dst):
    """answer 'can src reach dst?' as one Cypher traversal, timed, and show the same question as SQL. the SQL is
    the query a relational store would need: one self-join per hop, and a different query for each possible depth.
    we time the real Cypher run; the SQL is shown as what you would have to write, not benchmarked."""
    for node_id in (src, dst):
        if not session.run("MATCH (n {id:$id}) RETURN n LIMIT 1", id=node_id).single():
            return {"error": f"unknown node {node_id}"}
    cypher = (f"MATCH p = shortestPath((s {{id:$src}})-[:{REL}*..8]->(d {{id:$dst}}))\n"
              f"RETURN [n IN nodes(p) | n.id] AS ids, [r IN relationships(p) | type(r)] AS types")
    t0 = time.perf_counter()
    row = session.run(cypher, src=src, dst=dst).single()
    cypher_ms = round((time.perf_counter() - t0) * 1000, 2)
    path = {"ids": row["ids"], "types": row["types"]} if row else None
    hops = len(path["types"]) if path else 0

    if path:
        joins = "\n".join(f"  JOIN edges e{i} ON e{i-1}.dst = e{i}.src" if i else "  FROM edges e0"
                          for i in range(hops))
        sql = (f"-- one self-join per hop, and you must know the depth ({hops}) in advance\n"
               f"SELECT e0.src, e{hops - 1}.dst\n{joins}\n"
               f"WHERE e0.src = '{src}' AND e{hops - 1}.dst = '{dst}';")
        sql_note = (f"This path is {hops} hops, so the SQL is {hops} self-joins. A different depth needs a "
                    f"different query; 'any depth up to 8' needs 8 queries UNION-ed. The Cypher above is one query "
                    f"for every depth.")
    else:
        sql = ("-- with no fixed depth, SQL cannot ask 'is there any path' in one query;\n"
               "-- you UNION one query per possible hop count (1..8), each with that many self-joins.")
        sql_note = "No path exists. In SQL you would only learn that after running all 8 depth variants."

    return {
        "src": src, "dst": dst, "reachable": path is not None, "hops": hops, "path": path,
        "cypher": cypher, "cypher_ms": cypher_ms, "sql": sql, "sql_note": sql_note,
        "tags": [{"type": t, "tactic": TACTICS.get(_tac(t)), "technique": TECHNIQUES.get(_tech(t))}
                 for t in (path["types"] if path else [])],
    }


def _tac(edge_type):
    from .attack import EDGES
    return EDGES.get(edge_type, {}).get("tactic")


def _tech(edge_type):
    from .attack import EDGES
    return EDGES.get(edge_type, {}).get("technique")


def summary(session):
    """headline graph stats for the Neo4j banner: nodes, relationships, labels, and the algorithms in play."""
    counts = session.run(
        """
        MATCH (n) WHERE n:Entity
        WITH count(n) AS entities
        MATCH ()-[r]->() WHERE type(r) IN $rels
        RETURN entities, count(r) AS attack_edges
        """, rels=ATTACK_EDGES).single()
    total = session.run("MATCH (n) RETURN count(n) AS n").single()["n"]
    rels = session.run("MATCH ()-[r]->() RETURN count(r) AS n").single()["n"]
    return {"entities": counts["entities"] if counts else 0,
            "attack_edges": counts["attack_edges"] if counts else 0,
            "nodes_total": total, "relationships_total": rels,
            "cypher": CYPHER}


def has_gds(session):
    """true when this database has neo4j graph data science installed (aura free does not)."""
    try:
        session.run("RETURN gds.version() AS v").single()
        return True
    except Exception:  # unknown function: no graph data science here
        return False


def full_graph(session):
    """every entity and connection, with the algorithm results stored on each node, for drawing the whole graph:
    louvain community, pagerank (danger) and betweenness (choke_score). also the data model: how many of each kind
    of node, and how many connections of each type between each pair of kinds."""
    nodes = [dict(r) for r in session.run(
        """
        MATCH (n:Entity)
        RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind,
               coalesce(n.location, 'onprem') AS location, coalesce(n.critical, false) AS critical,
               n.zone AS zone, n.community AS community, n.danger AS pagerank, n.choke_score AS choke,
               coalesce(n.illustrative, false) AS illustrative, coalesce(n.kev, false) AS kev,
               n.hops_to_critical AS hops
        ORDER BY n.id
        """)]
    edges = [dict(r) for r in session.run(
        "MATCH (s:Entity)-[r]->(d:Entity) RETURN s.id AS src, type(r) AS type, d.id AS dst ORDER BY src, dst, type")]
    kind = {n["id"]: n["kind"] for n in nodes}
    attack = set(ATTACK_EDGES)
    for e in edges:
        e["attack"] = e["type"] in attack
    counts = {}
    for e in edges:
        key = (kind[e["src"]], e["type"], kind[e["dst"]])
        counts[key] = counts.get(key, 0) + 1
    schema = [{"src": s, "type": t, "dst": d, "count": c, "attack": t in attack,
               "tactic": TACTICS.get(_tac(t)), "technique": _tech(t)}
              for (s, t, d), c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    kinds = {}
    for n in nodes:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    # neo4j's visualization library (nvl) is licensed for use with neo4j aura only, so the dashboard draws with
    # nvl when this backend talks to aura and falls back to its own drawing on neo4j community
    aura = ".databases.neo4j.io" in os.environ.get("NEO4J_URI", "")
    return {"nodes": nodes, "edges": edges, "schema": schema, "kinds": kinds, "gds": has_gds(session), "aura": aura}
