"""how an incident started: the earliest initial-access alert, or an honest 'not seen'."""
from app.report import entry_line, entry_point


def test_entry_point_seen_and_not_seen():
    alerts = [{"id": "a2", "time": "2026-10-20T10:20:00", "name": "Remote logon", "tactic_id": "TA0008", "involves": ["server-7"]},
              {"id": "a1", "time": "2026-10-20T10:00:00", "name": "Phishing link clicked", "tactic_id": "TA0001",
               "technique_id": "T1566", "involves": ["laptop-42"]}]
    e = entry_point(alerts)
    assert e["seen"] and e["alert"] == "a1" and e["how"] == "Phishing"
    assert entry_line(e).startswith("Phishing (T1566) on laptop-42 at 10:00")
    e = entry_point(alerts[:1])
    assert not e["seen"] and e["stage"] == "Lateral Movement"
    assert entry_line(e).startswith("Entry point not seen")


def test_incident_api_has_the_entry(api):
    inc = next(a["incident_id"] for a in api.get("/api/alerts").json() if a["id"] == "a-01")
    assert api.get(f"/api/incidents/{inc}").json()["entry"]["seen"]
