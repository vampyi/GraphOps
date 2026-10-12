"""break tests: empty, very long and unexpected input."""
import json

import pytest

from app import load_demo


def test_empty_alert_file_loads_without_crashing(neo4j_driver, tmp_path):
    empty = tmp_path / "alerts.json"
    empty.write_text(json.dumps({"alerts": [], "events": []}))
    with neo4j_driver.session() as s:
        counts = load_demo.load(s, alerts_path=empty)
    assert counts["alerts"] == 0


def test_very_long_alert_name_is_kept(neo4j_driver, tmp_path):
    long_name = "x" * 10_000
    f = tmp_path / "alerts.json"
    f.write_text(json.dumps({"events": [], "alerts": [{
        "id": "long", "time": "2026-10-20T10:00:00", "name": long_name, "severity": "low",
        "tactic_id": None, "technique_id": None, "source_tool": "EDR", "involves": ["laptop-42"], "scenario": "noise"}]}))
    with neo4j_driver.session() as s:
        load_demo.load(s, alerts_path=f)
        assert len(s.run("MATCH (a:Alert {id: 'long'}) RETURN a.name AS n").single()["n"]) == 10_000


def test_unknown_node_label_is_rejected(neo4j_driver, tmp_path):
    f = tmp_path / "network.json"
    f.write_text(json.dumps({"nodes": [{"id": "x", "label": "Spaceship"}], "granted": [], "observed": []}))
    with neo4j_driver.session() as s, pytest.raises(ValueError):
        load_demo.load(s, network_path=f)


def test_cypher_injection_in_edge_type_is_rejected(neo4j_driver, tmp_path):
    f = tmp_path / "network.json"
    f.write_text(json.dumps({"nodes": [], "observed": [], "granted": [
        {"src": "a", "type": "MemberOf]->(x) DETACH DELETE x //", "dst": "b"}]}))
    with neo4j_driver.session() as s, pytest.raises(ValueError):
        load_demo.load(s, network_path=f)


def test_bad_verdict_and_unknown_alert(api):
    assert api.post("/api/alerts/a-03/verdict", json={"status": "maybe"}).status_code == 422
    assert api.post("/api/alerts/nope/verdict", json={"status": "real"}).status_code == 404
    assert api.get("/api/alerts/nope/blast-radius").status_code == 404
