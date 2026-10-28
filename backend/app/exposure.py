"""pre-incident exposure: the attack paths from low-trust machines to critical assets, the choke points they
share, and the smallest set of permissions whose removal cuts them.

the attack subgraph is pulled from neo4j (users, groups, computers and the edges in attack.EDGES) and analysed
with networkx, so it runs the same on a laptop and on aura free. every "cuts x of y" number is recomputed on the
graph with the removal applied, never estimated from a centrality score."""
from collections import Counter, defaultdict

import networkx as nx

from .attack import ATTACK_EDGES, EDGES, cost, describe_removal, tag

MAX_HOPS = 6
MAX_PATHS = 2000
SCOPES = ("low_trust", "all")


def fetch(session):
    """entities and attack edges as plain python, the input to everything below."""
    nodes = {r["id"]: dict(r) for r in session.run(
        """
        MATCH (n) WHERE n:Entity
        RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, coalesce(n.critical, false) AS critical, n.zone AS zone,
               n.community AS community, n.location AS location, coalesce(n.kev, false) AS kev, n.vulns AS vulns,
               n.name AS name, n.illustrative AS illustrative
        """)}
    rel = "|".join(ATTACK_EDGES)
    edges = [(r["s"], r["t"], r["d"]) for r in session.run(
        f"MATCH (s)-[r:{rel}]->(d) WHERE NOT s:Alert AND NOT d:Alert RETURN s.id AS s, type(r) AS t, d.id AS d")]
    return nodes, edges


def graph(nodes, edges):
    """a directed graph with one edge per (src, dst) pair. when two kinds of edge join the same pair, the easiest
    one sets the cost and all of them are remembered in `types`."""
    g = nx.DiGraph()
    for nid, n in nodes.items():
        g.add_node(nid, **{k: v for k, v in n.items() if k != "id"})
    for s, t, d in edges:
        if s not in nodes or d not in nodes or t not in EDGES:
            continue
        if g.has_edge(s, d):
            g[s][d]["types"].append(t)
            if cost(t) < g[s][d]["cost"]:
                g[s][d].update(type=t, cost=cost(t), p=EDGES[t]["p"])
        else:
            g.add_edge(s, d, type=t, types=[t], cost=cost(t), p=EDGES[t]["p"])
    return g


def sources_for(g, scope="low_trust"):
    """where an attacker starts. low_trust: machines in the low-trust zone (guest wifi, internet-facing, interns).
    all: every non-critical user and machine, for the question "if anything is compromised, what is exposed?"."""
    if scope == "all":
        # every non-critical user, machine and ai agent, plus the internet
        return sorted(n for n, d in g.nodes(data=True)
                      if not d.get("critical") and d.get("kind") in ("User", "Computer", "AIAgent", "Internet"))
    # low trust: machines in the low-trust zone, and the internet itself
    return sorted(n for n, d in g.nodes(data=True)
                  if (d.get("zone") == "low_trust" or d.get("kind") == "Internet") and not d.get("critical"))


def targets_for(g):
    return sorted(n for n, d in g.nodes(data=True) if d.get("critical"))


def _record(g, nodes, source, target):
    types = [g[a][b]["type"] for a, b in zip(nodes, nodes[1:])]
    likelihood = 1.0
    for t in types:
        likelihood *= EDGES[t]["p"]
    return {"source": source, "target": target, "nodes": nodes, "types": types, "hops": len(types),
            "likelihood": round(likelihood, 3), "most_likely": False}


def find_paths(g, sources, targets, max_hops=MAX_HOPS, limit=MAX_PATHS):
    """every hop-shortest path from each source to each critical asset it can reach within max_hops, plus the
    most likely path (dijkstra on -log p) when that is a different, longer route. returns the paths and the set
    of (source, target) pairs that are connected at all."""
    paths, pairs = [], set()
    for s in sources:
        if s not in g:
            continue
        within = nx.single_source_shortest_path_length(g, s, cutoff=max_hops)
        for t in targets:
            if t == s or t not in within:
                continue
            pairs.add((s, t))
            found = [_record(g, p, s, t) for p in nx.all_shortest_paths(g, s, t)]
            likely = nx.dijkstra_path(g, s, t, weight="cost")
            if len(likely) - 1 <= max_hops:
                rec = next((f for f in found if f["nodes"] == likely), None)
                if rec is None:
                    rec = _record(g, likely, s, t)
                    found.append(rec)
                rec["most_likely"] = True
            paths.extend(found)
            if len(paths) >= limit:
                return paths[:limit], pairs
    return paths, pairs


def reachable_pairs(g, sources, targets, max_hops=MAX_HOPS):
    out = set()
    for s in sources:
        if s not in g:
            continue
        within = nx.single_source_shortest_path_length(g, s, cutoff=max_hops)
        out.update((s, t) for t in targets if t != s and t in within)
    return out


def choke_points(g, paths, pairs):
    """how many paths, and how many (source, target) pairs, pass through each intermediate node and each edge.
    a pair counts for a node only if the node is on one of its paths; `share` is the fraction of all connected
    pairs that touch it. sources and targets themselves are not choke points."""
    node_paths, node_pairs = Counter(), defaultdict(set)
    edge_paths, edge_pairs = Counter(), defaultdict(set)
    for p in paths:
        pair = (p["source"], p["target"])
        for n in p["nodes"][1:-1]:
            node_paths[n] += 1
            node_pairs[n].add(pair)
        for a, b, t in zip(p["nodes"], p["nodes"][1:], p["types"]):
            edge_paths[(a, t, b)] += 1
            edge_pairs[(a, t, b)].add(pair)
    total = max(len(pairs), 1)
    nodes = [{"id": n, "kind": g.nodes[n].get("kind"), "critical": bool(g.nodes[n].get("critical")),
              "paths_through": c, "pairs_through": len(node_pairs[n]), "share": round(len(node_pairs[n]) / total, 3)}
             for n, c in node_paths.items()]
    nodes.sort(key=lambda x: (-x["pairs_through"], -x["paths_through"], x["id"]))
    edges = [{"src": a, "type": t, "dst": b, "paths_through": c, "pairs_through": len(edge_pairs[(a, t, b)]),
              "share": round(len(edge_pairs[(a, t, b)]) / total, 3), "action": describe_removal(a, t, b)}
             for (a, t, b), c in edge_paths.items()]
    edges.sort(key=lambda x: (-x["pairs_through"], -x["paths_through"], x["src"], x["dst"]))
    return nodes, edges


def without(g, remove_nodes=(), remove_edges=()):
    """a copy of the graph with nodes and (src, type, dst) edges taken out. a type of None removes every kind of
    edge between the pair."""
    h = g.copy()
    h.remove_nodes_from([n for n in remove_nodes if n in h])
    for src, typ, dst in remove_edges:
        if not h.has_edge(src, dst):
            continue
        types = [] if typ is None else [t for t in h[src][dst]["types"] if t != typ]
        if not types:
            h.remove_edge(src, dst)
        else:
            best = min(types, key=cost)
            h[src][dst].update(types=types, type=best, cost=cost(best), p=EDGES[best]["p"])
    return h


def simulate(g, sources, targets, remove_nodes=(), remove_edges=(), max_hops=MAX_HOPS, with_paths=True):
    """what the removal changes, measured on the changed graph: pairs still connected and the paths left."""
    before = reachable_pairs(g, sources, targets, max_hops)
    h = without(g, remove_nodes, remove_edges)
    after = reachable_pairs(h, sources, targets, max_hops)
    out = {"pairs_before": len(before), "pairs_after": len(after), "pairs_cut": len(before - after),
           "share_cut": round(len(before - after) / len(before), 3) if before else 0.0,
           "still_reachable": sorted([s, t] for s, t in after)}
    if with_paths:
        out["paths_after"], _ = find_paths(h, sources, targets, max_hops)
    return out


def min_cut(g, sources, targets):
    """the fewest edges whose removal disconnects every source from every target. every real edge has capacity 1;
    the edges from the super-source and to the super-sink have no capacity attribute, which networkx treats as
    unlimited, so the cut can only fall on real permissions and sessions. returns (src, types, dst) triples."""
    srcs = [s for s in sources if s in g]
    tgts = [t for t in targets if t in g]
    if not srcs or not tgts:
        return []
    h = nx.DiGraph()
    for u, v in g.edges():
        h.add_edge(u, v, capacity=1)
    for s in srcs:
        h.add_edge("__source__", s)
    for t in tgts:
        h.add_edge(t, "__sink__")
    if not nx.has_path(h, "__source__", "__sink__"):
        return []
    value, (left, right) = nx.minimum_cut(h, "__source__", "__sink__", capacity="capacity")
    if value == float("inf"):
        return []
    return sorted((u, list(g[u][v]["types"]), v) for u, v in h.edges() if u in left and v in right and g.has_edge(u, v))


def recommendations(g, sources, targets, chokes, max_hops=MAX_HOPS, top=5):
    """fixes worth a ticket, each with its exact effect. first the minimum cut as one package, then the top choke
    points one at a time, so an analyst can compare "remove these 2 permissions" with "harden this one server"."""
    out = []
    cut = min_cut(g, sources, targets)
    if cut:
        sim = simulate(g, sources, targets, remove_edges=[(u, None, v) for u, _, v in cut], max_hops=max_hops, with_paths=False)
        out.append({"kind": "cut", "title": f"Remove {len(cut)} permission{'s' if len(cut) != 1 else ''} or session{'s' if len(cut) != 1 else ''}",
                    "edges": [{"src": u, "types": ts, "dst": v, "action": describe_removal(u, ts[0], v)} for u, ts, v in cut],
                    **{k: sim[k] for k in ("pairs_before", "pairs_after", "pairs_cut", "share_cut")}})
    for c in chokes[:top]:
        if c["critical"]:
            continue  # a critical asset is what we protect, not what we remove
        sim = simulate(g, sources, targets, remove_nodes=[c["id"]], max_hops=max_hops, with_paths=False)
        verb = {"User": "Tier and reset the account", "Group": "Review every right held by the group",
                "Computer": "Isolate or harden the machine"}.get(c["kind"], "Harden")
        out.append({"kind": "node", "id": c["id"], "node_kind": c["kind"], "title": f"{verb} {c['id']}",
                    "paths_through": c["paths_through"], "pairs_through": c["pairs_through"],
                    **{k: sim[k] for k in ("pairs_before", "pairs_after", "pairs_cut", "share_cut")}})
    return out


def layers(paths, sources):
    """column for drawing each node: 0 for sources, then the fewest steps from any source along the paths."""
    layer = {s: 0 for s in sources}
    for p in paths:
        for i, n in enumerate(p["nodes"]):
            layer[n] = min(layer.get(n, i), i)
    return layer


def analyse(session, scope="low_trust", max_hops=MAX_HOPS):
    nodes, edges = fetch(session)
    g = graph(nodes, edges)
    return analyse_graph(g, scope, max_hops)


def analyse_graph(g, scope="low_trust", max_hops=MAX_HOPS):
    sources, targets = sources_for(g, scope), targets_for(g)
    paths, pairs = find_paths(g, sources, targets, max_hops)
    chokes, edge_chokes = choke_points(g, paths, pairs)
    layer = layers(paths, sources)
    on_paths = {n for p in paths for n in p["nodes"]}
    path_edges = {(a, t, b) for p in paths for a, b, t in zip(p["nodes"], p["nodes"][1:], p["types"])}
    pair_count = len({(s, t) for s in sources for t in targets if s != t})
    return {
        "scope": scope, "max_hops": max_hops,
        "sources": sources, "targets": targets,
        "pairs": {"possible": pair_count, "reachable": len(pairs)},
        "paths": sorted(paths, key=lambda p: (-p["likelihood"], p["hops"], p["source"], p["target"])),
        "chokepoints": chokes, "edge_chokepoints": edge_chokes,
        "recommendations": recommendations(g, sources, targets, chokes, max_hops),
        "nodes": [{"id": n, "kind": g.nodes[n].get("kind"), "critical": bool(g.nodes[n].get("critical")),
                   "zone": g.nodes[n].get("zone"), "community": g.nodes[n].get("community"),
                   "layer": layer.get(n, 0), "source": n in sources}
                  for n in sorted(on_paths | set(sources) | set(targets))],
        "edges": [{"src": a, "type": t, "dst": b, **{k: v for k, v in tag(t).items() if k != "type"}}
                  for a, t, b in sorted(path_edges)],
    }


def simulate_on(session, scope, remove_nodes, remove_edges, max_hops=MAX_HOPS):
    nodes, edges = fetch(session)
    g = graph(nodes, edges)
    sources, targets = sources_for(g, scope), targets_for(g)
    result = simulate(g, sources, targets, remove_nodes, [(e["src"], e.get("type"), e["dst"]) for e in remove_edges], max_hops)
    result.update(scope=scope, removed_nodes=list(remove_nodes), removed_edges=list(remove_edges))
    return result
