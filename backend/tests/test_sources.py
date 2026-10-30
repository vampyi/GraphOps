"""a real laptop reporting through osquery: token check, inventory in the graph, changes as alerts, kept on reload."""
import pytest

from app import seed

INV = {"host": "laptop-test", "label": "Test laptop", "owner": "Tester", "os": "macOS 15", "osquery_version": "5.24.0",
       "users": [{"name": "user-aaaa", "admin": True, "signed_in": True}, {"name": "user-bbbb", "admin": False, "signed_in": False}],
       "listening": [[7000, "ControlCenter"]], "firewall": False, "disk_encrypted": True}
TOKEN = {"X-GraphOps-Token": "test-token"}


@pytest.fixture()
def src_api(api, neo4j_driver, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "test-token")
    yield api
    # source records survive reloads by design, so remove them or they would leak into other tests
    with neo4j_driver.session() as s:
        s.run("MATCH (n) WHERE n:SourceRecord OR n:SourceEvent DETACH DELETE n")
        seed.load(s)


def test_writes_need_the_token(src_api):
    body = {"kind": "endpoint", "inventory": INV}
    assert src_api.post("/api/sources/laptop-test/inventory", json=body).status_code == 401
    assert src_api.post("/api/sources/laptop-test/inventory", json=body, headers={"X-GraphOps-Token": "no"}).status_code == 401


def test_laptop_in_graph_changes_as_alerts_and_kept_on_reload(src_api, neo4j_driver):
    assert src_api.post("/api/sources/laptop-test/inventory", json={"kind": "endpoint", "inventory": INV}, headers=TOKEN).status_code == 200
    r = src_api.post("/api/sources/laptop-test/events", headers=TOKEN, json={"events": [
        {"time": "2026-10-30T10:00:00+00:00", "kind": "firewall_off", "subject": "", "detail": "the host firewall is off"},
        {"time": "2026-10-30T10:01:00+00:00", "kind": "admin_added", "subject": "user-bbbb", "detail": "now admin"},
        {"time": "2026-10-30T10:02:00+00:00", "kind": "made_up", "subject": "x"}]})
    assert r.json()["stored"] == 2
    alerts = {a["name"]: a for a in src_api.get("/api/alerts").json() if a.get("source_tool") == "osquery"}
    assert set(alerts) == {"Firewall turned off", "New local administrator account: user-bbbb"}
    assert alerts["Firewall turned off"]["technique_id"] == "T1686"
    src = src_api.get("/api/sources").json()[0]
    assert src["label"] == "Test laptop" and src["admins"] == 1 and src["firewall"] is False and src["events"] == 2
    with neo4j_driver.session() as s:
        seed.load(s)  # a reload wipes the graph; the laptop and its alerts are drawn back
        assert s.run("MATCH (:User {id: 'ep:laptop-test/user-aaaa'})-[:AdminTo]->(:Computer {id: 'ep:laptop-test'}) "
                     "RETURN count(*) AS n").single()["n"] == 1
        assert s.run("MATCH (a:Alert {source_tool: 'osquery'}) RETURN count(a) AS n").single()["n"] == 2
