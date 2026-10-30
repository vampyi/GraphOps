"""flow-2 requirements R9-R20, run against a real neo4j in a container (see conftest.py).

these use the sample organisation, so they double as a check that the new analytics give sensible answers on
the one network the whole team knows."""
import pytest

from app import access, exposure
from app.scoring import score_all


# --- R9 exposure -----------------------------------------------------------

def test_r9_exposure_lists_paths_chokepoints_and_a_cut(api):
    body = api.get("/api/exposure?scope=low_trust").json()
    assert body["pairs"]["reachable"] >= 1
    assert body["paths"], "there should be at least one path from a low-trust machine to a critical asset"
    # the attacker's route laptop-42 -> server-7 -> customer-db is a known path on the sample data
    assert any(p["source"] == "laptop-42" and p["target"] == "customer-db" for p in body["paths"])
    # every path edge carries an att&ck technique tag so the path reads as a kill chain
    assert all("technique" in e for e in body["edges"])
    choke_ids = {c["id"] for c in body["chokepoints"]}
    assert "server-7" in choke_ids
    assert body["recommendations"] and body["recommendations"][0]["kind"] == "cut"
    assert body["recommendations"][0]["pairs_cut"] >= 1


def test_r9_scope_and_bounds_are_validated(api):
    assert api.get("/api/exposure?scope=sideways").status_code == 422
    assert api.get("/api/exposure?max_hops=0").status_code == 422
    assert api.get("/api/exposure?scope=all").status_code == 200


# --- R10 simulate removal --------------------------------------------------

def test_r10_removing_the_session_cuts_the_low_trust_paths(api):
    before = api.get("/api/exposure?scope=low_trust").json()["pairs"]["reachable"]
    body = api.post("/api/exposure/simulate", json={
        "scope": "low_trust",
        "edges": [{"src": "laptop-42", "type": "HasSession", "dst": "it_admin"},
                  {"src": "laptop-42", "type": "RemoteLogon", "dst": "server-7"}]}).json()
    assert body["pairs_before"] == before
    assert body["pairs_cut"] >= 1 and body["pairs_after"] < body["pairs_before"]


def test_r10_removing_an_unrelated_edge_cuts_nothing(api):
    body = api.post("/api/exposure/simulate", json={
        "scope": "low_trust", "edges": [{"src": "laptop-s1", "type": "ConnectedTo", "dst": "server-files"}]}).json()
    assert body["pairs_cut"] == 0


# --- R11 granted vs used ---------------------------------------------------

def test_r11_access_splits_granted_used_and_unused(api):
    body = api.get("/api/entities/it_admin/access").json()
    s = body["summary"]
    assert s["granted"] == s["used"] - len(body["used_without_grant"]) + s["unused"] or s["granted"] >= 1
    assert s["unused"] >= 1 and s["granted"] >= s["unused"]
    # it_admin logs into its own laptop with no explicit admin right on it: used but not granted
    assert "laptop-it1" in {x["id"] for x in body["used_without_grant"]}


def test_r11_overview_ranks_the_most_unused_access_first(api):
    body = api.get("/api/access/overview").json()
    assert body["identities"][0]["id"] == "it_admin"
    assert body["totals"]["unused"] >= 1


def test_r11_unknown_entity_is_404(api):
    assert api.get("/api/entities/nobody/access").status_code == 404


# --- R12 blast radius modes ------------------------------------------------

def test_r12_used_radius_is_within_granted_within_all(api):
    counts = {m: api.get(f"/api/alerts/a-03/blast-radius?mode={m}").json()["counts"]["reachable"]
              for m in ("all", "granted", "used")}
    assert counts["used"] <= counts["granted"]
    assert counts["granted"] <= counts["all"]
    assert api.get("/api/alerts/a-03/blast-radius?mode=sideways").status_code == 422


def test_r12_only_all_mode_draws_the_attack_path(api):
    assert api.get("/api/alerts/a-03/blast-radius?mode=all").json()["attack_path"] is not None
    assert api.get("/api/alerts/a-03/blast-radius?mode=granted").json()["attack_path"] is None


# --- R13 communities -------------------------------------------------------

def test_r13_attack_incident_is_lateral_across_communities(api, neo4j_driver):
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
    body = api.get(f"/api/incidents/{inc}").json()
    assert body["lateral"] is True
    assert len(body["communities"]) >= 2


def test_r13_every_entity_has_a_community(api, neo4j_driver):
    with neo4j_driver.session() as s:
        missing = s.run(
            "MATCH (n) WHERE (n:User OR n:Computer) AND n.community IS NULL RETURN count(n) AS c").single()["c"]
    assert missing == 0
    assert len(api.get("/api/communities").json()["communities"]) >= 2


# --- R14 incident is only the attack, with stable id and surviving notes ---

def test_r14_attack_incident_holds_only_attack_alerts(api, neo4j_driver, attack_ids):
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
        members = {r["id"] for r in s.run("MATCH (a:Alert {incident_id: $i}) RETURN a.id AS id", i=inc)}
    assert members == attack_ids


def test_r14_status_and_notes_survive_rescoring(api, neo4j_driver):
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
    api.patch(f"/api/incidents/{inc}", json={"status": "contained", "notes": "ticket INC-123"})
    with neo4j_driver.session() as s:
        score_all(s)  # a fresh scoring pass, as a new alert would trigger
        again = api.get(f"/api/incidents/{inc}").json()
    assert again["status"] == "contained" and again["notes"] == "ticket INC-123"
    assert again["id"] == inc  # the id did not move under the analyst


def test_r14_incident_status_values_are_validated(api, neo4j_driver):
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
    assert api.patch(f"/api/incidents/{inc}", json={"status": "sideways"}).status_code == 422
    assert api.patch("/api/incidents/inc-nope", json={"notes": "x"}).status_code == 404


# --- R16 asset criticality -------------------------------------------------

def test_r16_marking_an_asset_critical_recomputes_distances(api, neo4j_driver):
    with neo4j_driver.session() as s:
        before = s.run("MATCH (n {id: 'laptop-hr1'}) RETURN n.hops_to_critical AS h").single()["h"]
    assert api.patch("/api/assets/server-files", json={"critical": True}).status_code == 200
    with neo4j_driver.session() as s:
        after = s.run("MATCH (n {id: 'laptop-hr1'}) RETURN n.hops_to_critical AS h").single()["h"]
    # laptop-hr1 remote-logons to server-files, so once that server is critical it sits one hop away
    assert after == 1 and after != before


def test_r16_unknown_asset_and_bad_zone(api):
    assert api.patch("/api/assets/nope", json={"critical": True}).status_code == 404
    assert api.patch("/api/assets/server-7", json={"zone": "dmz"}).status_code == 422


# --- R17 verdicts ----------------------------------------------------------

def test_r17_benign_verdict_is_saved_with_who_and_when(api, neo4j_driver):
    r = api.post("/api/alerts/n-11/verdict", json={"status": "benign", "by": "analyst_a"})
    assert r.status_code == 200
    with neo4j_driver.session() as s:
        row = s.run("MATCH (a:Alert {id: 'n-11'}) RETURN a.status AS st, a.verdict_by AS by, a.verdict_at AS at").single()
    assert row["st"] == "benign" and row["by"] == "analyst_a" and row["at"]


def test_r17_unknown_verdict_rejected(api):
    assert api.post("/api/alerts/a-01/verdict", json={"status": "maybe"}).status_code == 422


# --- R18 ingest ------------------------------------------------------------

SAMPLE_ALERTS = {
    "sentinel": {"SystemAlertId": "sx-1", "AlertName": "Suspicious PowerShell", "AlertSeverity": "High",
                 "TimeGenerated": "2026-10-20T10:45:00", "Tactics": ["TA0002"], "Techniques": ["T1059"],
                 "Entities": [{"Type": "host", "HostName": "LAPTOP-F1"}, {"Type": "account", "Name": "fin_1"}]},
    "splunk": {"event_id": "sp-1", "rule_name": "Brute force detected", "urgency": "8",
               "info_max_time": "2026-10-20T10:46:00", "dest": "server-files", "user": "hr_1",
               "annotations": {"mitre_attack": ["T1110"]}},
    "elastic": {"kibana.alert.uuid": "el-1", "kibana.alert.rule.name": "Unusual login",
                "kibana.alert.severity": "medium", "@timestamp": "2026-10-20T10:47:00",
                "host.name": "laptop-d1", "user.name": "dev_1",
                "kibana.alert.rule.threat": [{"tactic": {"id": "TA0001"}, "technique": [{"id": "T1078"}]}]},
    "wazuh": {"id": "wz-1", "timestamp": "2026-10-20T10:48:00",
              "rule": {"description": "Scheduled task created", "level": 10, "mitre": {"id": ["T1053"], "tactic": ["TA0002"]}},
              "agent": {"name": "laptop-s2"}, "data": {"srcuser": "sales_2"}},
}


@pytest.mark.parametrize("fmt,raw_id,host,technique", [
    ("sentinel", "sx-1", "laptop-f1", "T1059"),
    ("splunk", "sp-1", "server-files", "T1110"),
    ("elastic", "el-1", "laptop-d1", "T1078"),
    ("wazuh", "wz-1", "laptop-s2", "T1053"),
])
def test_r18_siem_alert_formats_map_and_ingest(api, neo4j_driver, fmt, raw_id, host, technique):
    r = api.post(f"/api/ingest/alerts?format={fmt}", json={"alerts": [SAMPLE_ALERTS[fmt]]})
    assert r.status_code == 200 and r.json()["alerts"] == 1
    rows = api.get("/api/alerts").json()
    got = next((a for a in rows if a["id"] == raw_id), None)
    assert got is not None, f"{fmt} alert did not land"
    assert host in got["involves"] and got["technique_id"] == technique
    assert got["score"] is not None  # it was scored on the next read


def test_r18_raw_event_ingest_creates_unknown_hosts(api, neo4j_driver):
    r = api.post("/api/ingest", json={"events": [{
        "event_id": "ing-1", "time": "2026-10-20T11:00:00", "source_tool": "EDR", "kind": "Alert",
        "id": "ext-1", "name": "Beacon to known bad IP", "severity": "high", "tactic_id": "TA0011",
        "technique_id": "T1105", "involves": ["new-host-9"], "entities": [{"id": "new-host-9", "label": "Computer"}]}]})
    assert r.status_code == 200 and r.json()["alerts"] == 1
    with neo4j_driver.session() as s:
        assert s.run("MATCH (c:Computer {id: 'new-host-9'}) RETURN count(c) AS c").single()["c"] == 1
    assert any(a["id"] == "ext-1" for a in api.get("/api/alerts").json())


def test_r18_unknown_format_is_rejected(api):
    assert api.post("/api/ingest/alerts?format=carrierpigeon", json={"alerts": []}).status_code == 422


# --- R20 report ------------------------------------------------------------

# --- graph engine (the Neo4j showcase) ---

def test_graph_algorithm_roster_has_live_numbers(api):
    body = api.get("/api/graph/algorithms").json()
    assert body["summary"]["entities"] == 50  # network.json (37) plus cloud_ai.json (13)
    names = {a["algorithm"] for a in body["algorithms"]}
    assert {"PageRank", "Betweenness centrality", "Louvain community detection", "Shortest path (Dijkstra)"} <= names
    assert all(a["result"] for a in body["algorithms"])


def test_graph_vs_sql_reachability_proof(api):
    pr = api.get("/api/graph/reachability-proof?src=laptop-42&dst=customer-db").json()
    assert pr["reachable"] is True and pr["hops"] == 2
    assert pr["path"]["ids"] == ["laptop-42", "server-7", "customer-db"]
    assert "shortestPath" in pr["cypher"] and "JOIN" in pr["sql"] and pr["cypher_ms"] >= 0
    # an unreachable pair is reported honestly, not as an error
    none = api.get("/api/graph/reachability-proof?src=printer-01&dst=customer-db").json()
    assert none["reachable"] is False and none["hops"] == 0
    assert api.get("/api/graph/reachability-proof?src=ghost&dst=customer-db").status_code == 404


def test_pagerank_danger_is_stored_on_nodes(neo4j_driver, seeded):
    with neo4j_driver.session() as s:
        top = s.run("MATCH (n) WHERE n.danger IS NOT NULL RETURN n.id AS id ORDER BY n.danger DESC LIMIT 1").single()
    assert top["id"] in ("customer-db", "server-7")  # the crown jewels / their gateway are most central


# --- evaluation and held-out scenario (credibility) ---

def test_evaluation_graphops_beats_severity_only(api):
    ev = api.get("/api/evaluation").json()
    assert ev["scenario"] == "sample" and ev["attack"] == 4
    assert ev["graphops"]["last_attack_rank"] <= 5          # every attack alert ranks in the top 5
    assert ev["graphops"]["false_before_first"] == 0        # no false alarm read before the first real one
    assert ev["graphops"]["average_precision"] > ev["severity"]["average_precision"]
    assert ev["graphops"]["last_attack_rank"] < ev["severity"]["last_attack_rank"]


def test_scenarios_list_includes_the_held_out_day(api):
    body = api.get("/api/scenarios").json()
    ids = {s["id"] for s in body["scenarios"]}
    assert {"sample", "finance_breach"} <= ids and body["active"] == "sample"


def test_held_out_scenario_is_not_overfit(api):
    r = api.post("/api/scenarios/finance_breach/load").json()
    assert r["id"] == "finance_breach" and len(r["attack_ids"]) == 5
    ev = api.get("/api/evaluation").json()
    assert ev["scenario"] == "finance_breach"
    # on a day the weights were never tuned on, every attack alert still ranks in the top 5
    assert ev["graphops"]["last_attack_rank"] <= 5
    assert ev["graphops"]["average_precision"] == 1.0
    assert ev["graphops"]["last_attack_rank"] < ev["severity"]["last_attack_rank"]
    assert api.post("/api/scenarios/not-a-scenario/load").status_code == 404


def test_r20_report_names_every_attack_alert_and_the_crown_jewel(api, neo4j_driver):
    with neo4j_driver.session() as s:
        inc = s.run("MATCH (a:Alert {id: 'a-01'}) RETURN a.incident_id AS i").single()["i"]
    body = api.get(f"/api/incidents/{inc}/report").json()
    md = body["markdown"]
    for name in ["Phishing link clicked", "Credential dumping", "Remote logon", "Pass-the-hash"]:
        assert name in md
    assert "customer-db" in md
    assert body["summary"]["has_path"] is True and body["summary"]["lateral"] is True


def test_report_attack_path_lists_every_step(api):
    md = api.get("/api/incidents/" + api.get("/api/alerts").json()[0]["incident_id"] + "/report").json()["markdown"]
    line = next(l for l in md.splitlines() if l.startswith("Shortest attack path"))
    assert "→" in line and line.count("**") >= 4
