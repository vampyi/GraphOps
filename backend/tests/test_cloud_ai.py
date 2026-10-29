"""cloud resources, ai agents and vulnerabilities in the sample organisation, and the attack paths through them."""


def path_nodes(api, src, target):
    return [p["nodes"] for p in api.get(f"/api/explore/{src}?max_hops=8").json()["paths"] if p["target"] == target]


def test_php_vulnerability_comes_from_the_snapshot(api):
    vulns = {v["cve"]: v for v in api.get("/api/vulnerabilities").json()}
    php2shell = vulns["CVE-2026-109619"]
    assert php2shell["kev"] and php2shell["kev_added"] == "2026-10-26"
    assert php2shell["host"] == "web01" and php2shell["internet_exposed"] and php2shell["software"] == "php 8.3.30"


def test_internet_reaches_domain_admins_through_php2shell(api):
    paths = path_nodes(api, "internet", "g_domain_admins")
    assert ["internet", "web01", "svc_web", "g_appadmins", "app01", "it_admin", "g_domain_admins"] in paths


def test_on_prem_user_reaches_cloud_key_vault_through_an_ai_agent(api):
    assert ["fin_1", "fin_1@cloud", "finance-agent", "sp-finance", "kv-prod"] in path_nodes(api, "fin_1", "kv-prod")


def test_prompt_injection_path_to_a_jump_server(api):
    d = api.get("/api/explore/internet?max_hops=8").json()
    ids = {n["id"] for n in d["nodes"]}
    assert {"support-inbox", "support-agent", "ops-mcp", "jump-01"} <= ids
    step = next(s for p in d["paths"] for s in p["steps"] if s["type"] == "FeedsUntrustedInput")
    assert step["technique"] == "AML.T0051.001"


def test_every_node_has_a_location(neo4j_driver, seeded):
    with neo4j_driver.session() as s:
        rows = {r["loc"]: r["n"] for r in s.run("MATCH (n:Entity) RETURN n.location AS loc, count(*) AS n")}
    assert set(rows) == {"onprem", "cloud", "external"} and rows["cloud"] == 6


def test_path_through_web01_needs_the_vulnerability(api, neo4j_driver):
    """being on the internet is not a way in by itself: without an exploitable cve, web01 is out of reach."""
    from app import vulns
    with neo4j_driver.session() as s:
        vulns.apply(s, {"fetched": None, "by_cpe": {}})  # as if php had been patched
    reach = {n["id"] for n in api.get("/api/explore/internet?max_hops=8").json()["nodes"]}
    assert "web01" not in reach and "support-agent" in reach
    with neo4j_driver.session() as s:
        vulns.refresh(s, live=False)
    assert "web01" in {n["id"] for n in api.get("/api/explore/internet?max_hops=8").json()["nodes"]}


def test_full_graph_carries_algorithm_results_and_the_data_model(api):
    g = api.get("/api/graph/full").json()
    ids = {n["id"] for n in g["nodes"]}
    assert len(ids) == 50 and all(e["src"] in ids and e["dst"] in ids for e in g["edges"])
    assert all(n["pagerank"] is not None and n["choke"] is not None for n in g["nodes"])
    assert g["kinds"]["AIAgent"] == 2 and g["kinds"]["CloudResource"] == 2
    rows = {(r["src"], r["type"], r["dst"]): r for r in g["schema"]}
    assert rows[("Group", "AdminTo", "Computer")]["attack"]
    assert rows[("CloudResource", "FeedsUntrustedInput", "AIAgent")]["technique"] == "AML.T0051.001"
    assert sum(r["count"] for r in g["schema"]) == len(g["edges"])
