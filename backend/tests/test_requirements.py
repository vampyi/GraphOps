"""one test per requirement in PROJECT_SPEC.md, run against a real neo4j in a container."""
from app.story import write_story


def test_r1_loads_demo_with_one_command(demo):
    assert demo == {"nodes": 37, "edges": 53, "alerts": 30}


def test_r2_inbox_shows_every_alert_highest_first(api, demo):
    rows = api.get("/api/alerts").json()
    assert len(rows) == demo["alerts"]
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    assert all(r["reasons"] is not None for r in rows)


def test_r3_known_hops_to_critical(neo4j_driver, demo):
    with neo4j_driver.session() as s:
        hops = {r["id"]: r["h"] for r in s.run(
            "MATCH (n) WHERE n.id IN ['customer-db', 'server-7', 'laptop-42', 'printer-01'] "
            "RETURN n.id AS id, n.hops_to_critical AS h")}
    assert hops == {"customer-db": 0, "server-7": 1, "laptop-42": 2, "printer-01": None}


def test_r4_blast_radius_rings(api):
    body = api.get("/api/alerts/a-03/blast-radius").json()
    by_id = {n["id"]: n["hop"] for n in body["nodes"]}
    assert by_id["server-7"] == 0
    assert by_id["customer-db"] == 1
    assert by_id["g_domain_admins"] == 1
    assert by_id["dc-01"] == 2
    assert max(by_id.values()) <= 3


def test_r5_attack_is_one_incident_in_attack_order(neo4j_driver, demo, attack_ids):
    with neo4j_driver.session() as s:
        rows = [dict(r) for r in s.run(
            "MATCH (a:Alert) WHERE a.id IN $ids RETURN a.incident_id AS inc, a.tactic_id AS tac ORDER BY a.time",
            ids=list(attack_ids))]
    assert len({r["inc"] for r in rows}) == 1
    order = ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008"]
    positions = [order.index(r["tac"]) for r in rows]
    assert positions == sorted(positions)


def test_r6_story_drops_invented_citations(neo4j_driver, demo):
    def fake_llm(facts):
        return [{"text": "A phishing link was clicked.", "cites": ["a-01"]},
                {"text": "The attacker also hit the payroll server.", "cites": ["payroll-99"]}]
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
        result = write_story(s, inc, llm=fake_llm)
    assert [x["text"] for x in result["sentences"]] == ["A phishing link was clicked."]
    assert result["dropped"][0]["cites"] == ["payroll-99"]
    assert result["status"] == "needs analyst approval"


def test_r6_story_falls_back_to_facts_without_llm(neo4j_driver, demo):
    def broken_llm(facts):
        raise RuntimeError("no access")
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
        result = write_story(s, inc, llm=broken_llm)
    assert result["source"] == "facts"
    assert len(result["sentences"]) >= 4


def test_r7_verdict_is_saved(api, neo4j_driver):
    assert api.post("/api/alerts/a-03/verdict", json={"status": "real"}).status_code == 200
    with neo4j_driver.session() as s:
        assert s.run("MATCH (a:Alert {id: 'a-03'}) RETURN a.status AS st").single()["st"] == "real"


def test_r8_attack_ranks_in_top_5(api, attack_ids):
    top5 = [r["id"] for r in api.get("/api/alerts").json()[:5]]
    assert attack_ids <= set(top5)
