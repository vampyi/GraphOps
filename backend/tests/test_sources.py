"""a real ai agent reporting into GraphOps: token check, access scan, live activity, and paths through it."""
import pytest

from app import seed

INVENTORY = {
    "agent": {"id": "claude-code-test", "name": "Claude Code", "platform": "Anthropic Claude Code", "host": "test laptop"},
    "folders": [{"id": "folder:work", "name": "work"}],
    "secrets": [{"id": "secret:work/.env", "name": ".env", "folder": "folder:work", "services": ["svc:db"]}],
    "services": [{"id": "svc:db", "name": "Production database", "critical": True},
                 {"id": "svc:git", "name": "GitHub", "critical": False}],
    "accounts": [{"service": "svc:git", "account": "someone"}],
    "tools": [{"id": "tool:web", "name": "Web fetch", "untrusted_input": True}],
}
TOKEN = {"X-GraphOps-Token": "test-token"}


@pytest.fixture()
def agent_api(api, neo4j_driver, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "test-token")
    yield api
    # source records survive reloads by design, so remove them or they would leak into other tests
    with neo4j_driver.session() as s:
        s.run("MATCH (n) WHERE n:SourceRecord OR n:SourceEvent DETACH DELETE n")
        seed.load(s)


def test_writes_need_the_token(agent_api):
    body = {"kind": "ai_agent", "inventory": INVENTORY}
    assert agent_api.post("/api/sources/claude-code-test/inventory", json=body).status_code == 401
    assert agent_api.post("/api/sources/claude-code-test/inventory", json=body,
                          headers={"X-GraphOps-Token": "wrong"}).status_code == 401


def test_agent_access_activity_and_paths(agent_api, neo4j_driver):
    assert agent_api.post("/api/sources/claude-code-test/inventory",
                          json={"kind": "ai_agent", "inventory": INVENTORY}, headers=TOKEN).status_code == 200
    agent_api.post("/api/sources/claude-code-test/events", headers=TOKEN, json={"events": [
        {"tool": "Bash", "target": "svc:git", "detail": "ran git"},
        {"tool": "Read", "target": "secret:work/.env", "detail": "Read .env"}]})
    v = agent_api.get("/api/agents/claude-code-test").json()
    assert v["summary"]["secrets"] == 1 and v["summary"]["critical_services"] == 1
    assert {s["id"]: s["used"] for s in v["secrets"]} == {"secret:work/.env": 1}
    assert [p["nodes"] for p in v["attack_paths"]] == [
        ["internet", "claude-code-test", "folder:work", "secret:work/.env", "svc:db"]]
    assert v["attack_paths"][0]["types"] == ["FeedsUntrustedInput", "CanRead", "Contains", "HoldsKeyFor"]

    # loading another day rebuilds the graph; the agent is drawn back in with its activity
    with neo4j_driver.session() as s:
        seed.load(s)
    v = agent_api.get("/api/agents/claude-code-test").json()
    assert v["summary"]["used"] == 2 and len(v["events"]) == 2
