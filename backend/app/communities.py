"""communities: the groups of users and machines that normally work together, found with louvain over observed
activity (logins, remote logons and network connections, read as undirected). the community number is stored
on each node as `community`, renumbered 1, 2, 3... from the largest down so the dashboard can name them.

uses neo4j graph data science when the database has it and the same algorithm in python (networkx) when it does
not, for example on aura free. groups have no activity, so they get no community."""
import networkx as nx

ACTIVITY = ["LoggedInto", "RemoteLogon", "ConnectedTo"]
LABELS = ["User", "Computer"]
SEED = 7


def present_types(session):
    have = {r["t"] for r in session.run("MATCH ()-[r]->() RETURN DISTINCT type(r) AS t")}
    return [t for t in ACTIVITY if t in have]


def run(session):
    session.run("MATCH (n) WHERE n:User OR n:Computer OR n:Group SET n.community = null")
    if not present_types(session):
        return
    try:
        _gds(session)
    except Exception as exc:  # graph data science not installed on this database
        if "gds" not in str(exc).lower() and "procedure" not in str(exc).lower():
            raise
        _python(session)
    _renumber(session)


def _gds(session):
    session.run("CALL gds.graph.drop('activity', false) YIELD graphName RETURN graphName").consume()
    session.run("CALL gds.graph.project('activity', $labels, $rels) YIELD graphName RETURN graphName",
                labels=LABELS, rels={t: {"orientation": "UNDIRECTED"} for t in present_types(session)}).consume()
    session.run("CALL gds.louvain.write('activity', {writeProperty: 'community'}) YIELD communityCount RETURN communityCount").consume()
    session.run("CALL gds.graph.drop('activity') YIELD graphName RETURN graphName").consume()


def _python(session):
    g = nx.Graph()
    for r in session.run("MATCH (n) WHERE n:User OR n:Computer RETURN n.id AS id"):
        g.add_node(r["id"])
    rel = "|".join(present_types(session))
    for r in session.run(f"MATCH (s)-[:{rel}]-(d) WHERE (s:User OR s:Computer) AND (d:User OR d:Computer) RETURN s.id AS s, d.id AS d"):
        g.add_edge(r["s"], r["d"])
    rows = [{"id": n, "c": i} for i, com in enumerate(nx.community.louvain_communities(g, seed=SEED)) for n in com]
    session.run("UNWIND $rows AS row MATCH (n {id: row.id}) SET n.community = row.c", rows=rows)


def _renumber(session):
    """1 for the largest community, 2 for the next and so on. ties go to the community with the first id."""
    sizes = [(r["c"], r["n"], r["first"]) for r in session.run(
        "MATCH (n) WHERE n.community IS NOT NULL RETURN n.community AS c, count(*) AS n, min(n.id) AS first")]
    sizes.sort(key=lambda x: (-x[1], x[2]))
    session.run("UNWIND $rows AS row MATCH (n) WHERE n.community = row.old SET n.community_new = row.new",
                rows=[{"old": c, "new": i + 1} for i, (c, _, _) in enumerate(sizes)])
    session.run("MATCH (n) WHERE n.community_new IS NOT NULL SET n.community = n.community_new REMOVE n.community_new")


def summary(session):
    """each community with its members, busiest first, so the dashboard can label it by its best-known members."""
    rows = session.run(
        """
        MATCH (n) WHERE n.community IS NOT NULL AND (n:User OR n:Computer)
        OPTIONAL MATCH (n)-[r:LoggedInto|RemoteLogon|ConnectedTo]-()
        WITH n, count(r) AS degree
        ORDER BY degree DESC, n.id
        RETURN n.community AS id,
               collect({id: n.id, kind: [l IN labels(n) WHERE l <> 'Entity'][0], critical: coalesce(n.critical, false), degree: degree}) AS members
        ORDER BY size(members) DESC, id
        """)
    out = []
    for r in rows:
        members = r["members"]
        label = ", ".join(m["id"] for m in members[:3]) + (f" +{len(members) - 3}" if len(members) > 3 else "")
        out.append({"id": r["id"], "size": len(members), "label": label, "members": members,
                    "critical": [m["id"] for m in members if m["critical"]]})
    return out
