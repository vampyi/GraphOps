"""background graph analysis: work out slow graph facts ahead of time and save them on nodes."""

# edges an attacker can follow. HasSession points from a computer to the user whose
# credentials may be stolen there, so it is followed in its stored direction too.
ATTACK_EDGES = ["MemberOf", "AdminTo", "CanRDP", "GenericAll", "HasSession", "RemoteLogon"]
ENTITY_LABELS = ["User", "Group", "Computer"]
MAX_HOPS = 8


def attack_edge_types(session):
    present = {r["t"] for r in session.run("MATCH ()-[r]->() RETURN DISTINCT type(r) AS t")}
    return [t for t in ATTACK_EDGES if t in present]


def hops_to_critical(session):
    """fewest attack steps from each entity to the nearest critical asset."""
    rel = "|".join(attack_edge_types(session))
    session.run("MATCH (n) WHERE n:User OR n:Group OR n:Computer SET n.hops_to_critical = null")
    session.run("MATCH (n) WHERE (n:User OR n:Group OR n:Computer) AND n.critical = true SET n.hops_to_critical = 0")
    session.run(
        f"""
        MATCH (n) WHERE (n:User OR n:Group OR n:Computer) AND coalesce(n.critical, false) = false
        MATCH (c) WHERE (c:User OR c:Group OR c:Computer) AND c.critical = true
        MATCH p = shortestPath((n)-[:{rel}*..{MAX_HOPS}]->(c))
        WITH n, min(length(p)) AS hops
        SET n.hops_to_critical = hops
        """
    )


def critical_within_3(session):
    """how many critical assets an entity can reach within 3 attack steps (its blast radius)."""
    rel = "|".join(attack_edge_types(session))
    session.run(
        f"""
        MATCH (n) WHERE n:User OR n:Group OR n:Computer
        OPTIONAL MATCH (n)-[:{rel}*1..3]->(c) WHERE c.critical = true
        WITH n, count(DISTINCT c) AS crit
        SET n.critical_within_3 = crit
        """
    )


def choke_scores(session):
    """betweenness centrality on the attack graph, scaled to 0..1. uses neo4j graph data science when the
    database has it, and the same calculation in python (networkx) when it does not, for example on aura free."""
    try:
        _choke_scores_gds(session)
    except Exception as exc:  # graph data science not installed on this database
        if "gds" not in str(exc).lower() and "procedure" not in str(exc).lower():
            raise
        _choke_scores_python(session)
    top = session.run("MATCH (n) WHERE n.betweenness IS NOT NULL RETURN max(n.betweenness) AS m").single()["m"] or 1.0
    session.run(
        "MATCH (n) WHERE n.betweenness IS NOT NULL SET n.choke_score = n.betweenness / $top",
        top=top if top > 0 else 1.0,
    )


def _choke_scores_gds(session):
    session.run("CALL gds.graph.drop('attack', false) YIELD graphName RETURN graphName").consume()
    session.run(
        "CALL gds.graph.project('attack', $labels, $rels) YIELD graphName RETURN graphName",
        labels=ENTITY_LABELS, rels=attack_edge_types(session),
    ).consume()
    session.run("CALL gds.betweenness.write('attack', {writeProperty: 'betweenness'}) YIELD nodePropertiesWritten RETURN nodePropertiesWritten").consume()
    session.run("CALL gds.graph.drop('attack') YIELD graphName RETURN graphName").consume()


def _choke_scores_python(session):
    import networkx as nx
    rel = "|".join(attack_edge_types(session))
    g = nx.DiGraph()
    for r in session.run("MATCH (n) WHERE n:User OR n:Group OR n:Computer RETURN n.id AS id"):
        g.add_node(r["id"])
    for r in session.run(f"MATCH (s)-[:{rel}]->(d) RETURN s.id AS s, d.id AS d"):
        g.add_edge(r["s"], r["d"])
    scores = nx.betweenness_centrality(g, normalized=False)
    session.run(
        "UNWIND $rows AS row MATCH (n {id: row.id}) SET n.betweenness = row.b",
        rows=[{"id": k, "b": float(v)} for k, v in scores.items()],
    )


def danger_scores(session):
    """PageRank on the attack graph, scaled to 0..1 and saved as `danger`. the challenge names PageRank as a way
    to find the nodes that would cause the most disruption if compromised. uses neo4j graph data science when the
    database has it, and networkx when it does not."""
    try:
        _pagerank_gds(session)
    except Exception as exc:  # graph data science not installed on this database
        if "gds" not in str(exc).lower() and "procedure" not in str(exc).lower():
            raise
        _pagerank_python(session)
    top = session.run("MATCH (n) WHERE n.pagerank IS NOT NULL RETURN max(n.pagerank) AS m").single()["m"] or 1.0
    session.run("MATCH (n) WHERE n.pagerank IS NOT NULL SET n.danger = n.pagerank / $top",
                top=top if top > 0 else 1.0)


def _pagerank_gds(session):
    session.run("CALL gds.graph.drop('pr', false) YIELD graphName RETURN graphName").consume()
    session.run("CALL gds.graph.project('pr', $labels, $rels) YIELD graphName RETURN graphName",
                labels=ENTITY_LABELS, rels=attack_edge_types(session)).consume()
    session.run("CALL gds.pageRank.write('pr', {writeProperty: 'pagerank'}) YIELD nodePropertiesWritten RETURN nodePropertiesWritten").consume()
    session.run("CALL gds.graph.drop('pr') YIELD graphName RETURN graphName").consume()


def _pagerank_python(session):
    import networkx as nx
    rel = "|".join(attack_edge_types(session))
    g = nx.DiGraph()
    for r in session.run("MATCH (n) WHERE n:User OR n:Group OR n:Computer RETURN n.id AS id"):
        g.add_node(r["id"])
    for r in session.run(f"MATCH (s)-[:{rel}]->(d) RETURN s.id AS s, d.id AS d"):
        g.add_edge(r["s"], r["d"])
    scores = nx.pagerank(g) if g.number_of_edges() else {n: 0.0 for n in g}
    session.run("UNWIND $rows AS row MATCH (n {id: row.id}) SET n.pagerank = row.b",
                rows=[{"id": k, "b": float(v)} for k, v in scores.items()])


def run_all(session):
    hops_to_critical(session)
    critical_within_3(session)
    choke_scores(session)
    danger_scores(session)
    from .communities import run as detect_communities
    detect_communities(session)
