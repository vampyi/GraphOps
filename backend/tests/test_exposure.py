"""known-answer tests for the exposure analysis on a small graph, no database needed (requirements R9, R10)."""
from app import exposure
from app.attack import EDGES, describe_removal, tag

# two low-trust laptops hold a helpdesk admin's session. the helpdesk group administers a server where a database
# service account is signed in, and that account is a database admin. the admin is also a domain admin.
NODES = {
    "lap1": {"kind": "Computer", "zone": "low_trust", "critical": False},
    "lap2": {"kind": "Computer", "zone": "low_trust", "critical": False},
    "lap3": {"kind": "Computer", "zone": "low_trust", "critical": False},
    "admin": {"kind": "User", "critical": False},
    "hd": {"kind": "Group", "critical": False},
    "srv": {"kind": "Computer", "zone": "normal", "critical": False},
    "svc": {"kind": "User", "critical": False},
    "dba": {"kind": "Group", "critical": False},
    "db": {"kind": "Computer", "zone": "normal", "critical": True},
    "da": {"kind": "Group", "critical": True},
    "dc": {"kind": "Computer", "zone": "normal", "critical": True},
    "ops": {"kind": "Group", "critical": False},
    "printer": {"kind": "Computer", "zone": "low_trust", "critical": False},
}
EDGE_LIST = [
    ("lap1", "HasSession", "admin"), ("lap2", "HasSession", "admin"),
    ("admin", "MemberOf", "hd"), ("hd", "AdminTo", "srv"),
    ("srv", "HasSession", "svc"), ("svc", "MemberOf", "dba"), ("dba", "AdminTo", "db"),
    ("admin", "MemberOf", "da"), ("da", "AdminTo", "dc"),
    # lap3 can reach dc directly by remote desktop (1 hop, p 0.7) or through a group (2 hops, p 0.9)
    ("lap3", "CanRDP", "dc"), ("lap3", "MemberOf", "ops"), ("ops", "AdminTo", "dc"),
]


def build():
    return exposure.graph(NODES, EDGE_LIST)


def test_sources_and_targets():
    g = build()
    assert exposure.sources_for(g) == ["lap1", "lap2", "lap3", "printer"]
    assert exposure.targets_for(g) == ["da", "db", "dc"]
    assert "printer" in exposure.sources_for(g, "all") and "da" not in exposure.sources_for(g, "all")


def test_paths_and_reachable_pairs():
    g = build()
    paths, pairs = exposure.find_paths(g, exposure.sources_for(g), exposure.targets_for(g))
    assert pairs == {("lap1", "da"), ("lap1", "db"), ("lap1", "dc"), ("lap2", "da"), ("lap2", "db"), ("lap2", "dc"), ("lap3", "dc")}
    lap1_db = next(p for p in paths if (p["source"], p["target"]) == ("lap1", "db"))
    assert lap1_db["nodes"] == ["lap1", "admin", "hd", "srv", "svc", "dba", "db"]
    assert lap1_db["types"] == ["HasSession", "MemberOf", "AdminTo", "HasSession", "MemberOf", "AdminTo"]
    assert lap1_db["likelihood"] == round(0.6 * 1.0 * 0.9 * 0.6 * 1.0 * 0.9, 3)


def test_most_likely_path_can_be_longer_than_the_shortest():
    g = build()
    paths, _ = exposure.find_paths(g, ["lap3"], ["dc"])
    by_hops = {p["hops"]: p for p in paths}
    assert set(by_hops) == {1, 2}
    assert by_hops[1]["most_likely"] is False and by_hops[1]["types"] == ["CanRDP"]
    assert by_hops[2]["most_likely"] is True and by_hops[2]["likelihood"] == 0.9


def test_choke_points_rank_the_shared_admin_first():
    g = build()
    sources, targets = exposure.sources_for(g), exposure.targets_for(g)
    paths, pairs = exposure.find_paths(g, sources, targets)
    nodes, edges = exposure.choke_points(g, paths, pairs)
    assert nodes[0]["id"] == "admin" and nodes[0]["pairs_through"] == 6 and nodes[0]["share"] == round(6 / 7, 3)
    assert {n["id"] for n in nodes} >= {"admin", "hd", "srv", "svc", "dba", "da", "ops"}
    assert all(n["id"] not in sources and n["id"] not in ("db", "dc") for n in nodes)
    # admin -MemberOf-> da carries both laptops to both da and dc: 4 pairs, the most of any single edge
    top_edge = edges[0]
    assert (top_edge["src"], top_edge["type"], top_edge["dst"]) == ("admin", "MemberOf", "da")
    assert top_edge["pairs_through"] == 4 and top_edge["action"] == describe_removal(top_edge["src"], top_edge["type"], top_edge["dst"])


def test_simulated_removal_is_recomputed_exactly():
    g = build()
    sources, targets = exposure.sources_for(g), exposure.targets_for(g)
    r = exposure.simulate(g, sources, targets, remove_nodes=["hd"])
    assert (r["pairs_before"], r["pairs_after"], r["pairs_cut"]) == (7, 5, 2)
    assert ["lap1", "db"] not in r["still_reachable"] and ["lap1", "dc"] in r["still_reachable"]
    r = exposure.simulate(g, sources, targets, remove_edges=[("lap1", "HasSession", "admin"), ("lap2", "HasSession", "admin")])
    assert r["pairs_after"] == 1 and r["still_reachable"] == [["lap3", "dc"]]
    assert all(p["source"] == "lap3" for p in r["paths_after"])


def test_removing_one_kind_of_edge_keeps_the_other():
    g = exposure.graph({"a": {"kind": "User"}, "b": {"kind": "Computer", "critical": True}},
                       [("a", "AdminTo", "b"), ("a", "CanRDP", "b")])
    h = exposure.without(g, remove_edges=[("a", "AdminTo", "b")])
    assert h["a"]["b"]["types"] == ["CanRDP"] and h["a"]["b"]["p"] == EDGES["CanRDP"]["p"]
    assert not exposure.without(g, remove_edges=[("a", None, "b")]).has_edge("a", "b")


def test_min_cut_disconnects_everything_with_the_fewest_edges():
    g = build()
    sources, targets = exposure.sources_for(g), exposure.targets_for(g)
    cut = exposure.min_cut(g, sources, targets)
    # lap3 needs both of its routes cut, lap1 and lap2 need their sessions (or admin's two memberships): 4 edges
    assert len(cut) == 4
    r = exposure.simulate(g, sources, targets, remove_edges=[(u, None, v) for u, _, v in cut], with_paths=False)
    assert r["pairs_after"] == 0 and r["share_cut"] == 1.0
    assert exposure.min_cut(g, [], targets) == [] and exposure.min_cut(g, ["printer"], targets) == []


def test_recommendations_carry_exact_effects():
    g = build()
    out = exposure.analyse_graph(g)
    recs = out["recommendations"]
    assert recs[0]["kind"] == "cut" and recs[0]["pairs_cut"] == 7 and recs[0]["share_cut"] == 1.0
    assert all("action" in e for e in recs[0]["edges"])
    node_recs = [r for r in recs if r["kind"] == "node"]
    assert node_recs[0]["id"] == "admin" and node_recs[0]["pairs_cut"] == 6
    assert all(not NODES[r["id"]]["critical"] for r in node_recs)
    assert out["pairs"] == {"possible": 12, "reachable": 7}
    assert {e["type"] for e in out["edges"]} <= set(EDGES)
    assert all(e["technique"] == tag(e["type"])["technique"] for e in out["edges"])
    assert {n["id"]: n["layer"] for n in out["nodes"]}["admin"] == 1 and {n["id"]: n["layer"] for n in out["nodes"]}["printer"] == 0


def test_every_attack_edge_has_a_tag_and_a_fix():
    for t in EDGES:
        assert 0 < EDGES[t]["p"] <= 1
        assert tag(t)["step"]
        assert describe_removal("x", t, "y") != f"Remove x -{t}-> y"
