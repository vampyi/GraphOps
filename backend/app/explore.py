"""explore: everything one user, group or machine can reach, and the attack paths from it to critical assets.

paths come in four views: the shortest (fewest steps), the most likely (highest product of step likelihoods,
which can be longer), the paths an analyst has already secured (a step on them carries a recorded control,
such as "mfa enforced") and the paths that still need securing."""
import networkx as nx

from .attack import EDGES, tag
from .exposure import fetch, graph

MAX_HOPS = 8
PATHS_PER_TARGET = 4
MAX_PATHS = 40


def secured_steps(session):
    """steps an analyst marked as secured, keyed (src, type, dst)."""
    return {(r["s"], r["t"], r["d"]): r["note"] for r in session.run(
        "MATCH (s)-[r]->(d) WHERE r.secured = true RETURN s.id AS s, type(r) AS t, d.id AS d, r.secured_note AS note")}


def _path(g, nodes, secured):
    steps, likelihood, controls = [], 1.0, []
    for a, b in zip(nodes, nodes[1:]):
        types = g[a][b]["types"]
        # a step is blocked only if every way across it is secured; the easiest unsecured way decides its likelihood
        open_types = [t for t in types if (a, t, b) not in secured]
        t = min(open_types or types, key=lambda x: -EDGES[x]["p"])
        if not open_types:
            controls.append({"src": a, "type": t, "dst": b, "note": secured.get((a, t, b))})
        likelihood *= EDGES[t]["p"]
        steps.append({"src": a, "dst": b, **tag(t)})
    return {"nodes": nodes, "steps": steps, "hops": len(steps), "likelihood": round(likelihood, 3),
            "secured": bool(controls), "controls": controls}


def explore(session, entity_id, max_hops=MAX_HOPS):
    nodes, edges = fetch(session)
    if entity_id not in nodes:
        return None
    g = graph(nodes, edges)
    secured = secured_steps(session)
    hops = nx.single_source_shortest_path_length(g, entity_id, cutoff=max_hops)
    reach = [{"id": n, "hop": h, **{k: nodes[n].get(k) for k in ("kind", "critical", "zone", "community", "location", "kev", "vulns", "name", "illustrative")}}
             for n, h in sorted(hops.items(), key=lambda x: (x[1], x[0]))]
    keep = set(hops)
    edge_list = [{"src": s, "type": t, "dst": d, "secured": (s, t, d) in secured}
                 for s, t, d in edges if s in keep and d in keep and t in EDGES]

    targets = [n["id"] for n in reach if n["critical"] and n["id"] != entity_id]
    paths = []
    for t in targets:
        found = []
        shortest = [list(p) for p in nx.all_shortest_paths(g, entity_id, t)][:PATHS_PER_TARGET]
        likely = nx.dijkstra_path(g, entity_id, t, weight="cost")
        # the next most likely alternatives, in order of likelihood, up to a few more steps than the shortest
        alternatives = []
        for p in nx.shortest_simple_paths(g, entity_id, t, weight="cost"):
            if len(p) - 1 > max_hops + 1 or len(alternatives) >= PATHS_PER_TARGET:
                break
            alternatives.append(p)
        for p in shortest + [likely] + alternatives:
            if p not in found:
                found.append(p)
        min_hops = len(shortest[0]) - 1
        for p in found:
            rec = _path(g, p, secured)
            rec.update(target=t, shortest=len(p) - 1 == min_hops, most_likely=p == likely)
            paths.append(rec)
    paths.sort(key=lambda r: (-r["likelihood"], r["hops"]))
    paths = paths[:MAX_PATHS]
    kinds = {}
    for n in reach[1:]:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    by_location = {}
    for n in reach[1:]:
        by_location[n["location"] or "onprem"] = by_location.get(n["location"] or "onprem", 0) + 1
    return {"entity": {"id": entity_id, **{k: nodes[entity_id].get(k) for k in ("kind", "critical", "zone", "location", "name", "illustrative")}},
            "max_hops": max_hops, "nodes": reach, "edges": edge_list, "paths": paths,
            "summary": {"reachable": len(reach) - 1, "by_kind": kinds, "by_location": by_location, "critical": len(targets),
                        "paths": len(paths), "secured": sum(p["secured"] for p in paths),
                        "unsecured": sum(not p["secured"] for p in paths)}}


def set_secured(session, src, edge_type, dst, secured, note=None):
    if edge_type not in EDGES:
        raise ValueError(f"unknown step type {edge_type}")
    row = session.run(
        f"""
        MATCH (s {{id: $src}})-[r:{edge_type}]->(d {{id: $dst}})
        SET r.secured = $secured, r.secured_note = CASE WHEN $secured THEN $note ELSE null END
        RETURN count(r) AS n
        """, src=src, dst=dst, secured=secured, note=(note or "")[:200]).single()
    return row["n"]
