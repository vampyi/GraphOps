"""explore: reach from one system, the four path views, and recording a control on a step."""


def test_explore_reach_and_paths(api):
    d = api.get("/api/explore/laptop-42").json()
    ids = {n["id"] for n in d["nodes"]}
    assert {"server-7", "it_admin", "customer-db", "dc-01"} <= ids
    targets = {p["target"] for p in d["paths"]}
    assert {"customer-db", "g_domain_admins", "dc-01"} <= targets
    for t in targets:
        mine = [p for p in d["paths"] if p["target"] == t]
        assert any(p["shortest"] for p in mine) and sum(p["most_likely"] for p in mine) == 1
        assert min(p["hops"] for p in mine) == min(p["hops"] for p in mine if p["shortest"])
    # alternatives that are longer than the shortest route exist
    assert any(not p["shortest"] for p in d["paths"])
    assert d["summary"]["unsecured"] == len(d["paths"]) and d["summary"]["secured"] == 0


def test_securing_a_step_moves_paths_to_secured(api):
    r = api.post("/api/controls", json={"src": "laptop-42", "type": "HasSession", "dst": "it_admin", "note": "session cleared"})
    assert r.status_code == 200
    d = api.get("/api/explore/laptop-42").json()
    through = [p for p in d["paths"] if p["nodes"][:2] == ["laptop-42", "it_admin"]]
    assert through and all(p["secured"] and p["controls"][0]["note"] == "session cleared" for p in through)
    assert any(e["secured"] for e in d["edges"])
    api.post("/api/controls", json={"src": "laptop-42", "type": "HasSession", "dst": "it_admin", "secured": False})
    assert api.get("/api/explore/laptop-42").json()["summary"]["secured"] == 0


def test_bad_inputs(api):
    assert api.get("/api/explore/nope").status_code == 404
    assert api.post("/api/controls", json={"src": "a", "type": "Teleport", "dst": "b"}).status_code == 422
    assert api.post("/api/controls", json={"src": "laptop-42", "type": "AdminTo", "dst": "dc-01"}).status_code == 404
