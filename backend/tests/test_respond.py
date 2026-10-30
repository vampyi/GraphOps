"""responding to a confirmed incident: plan from the graph, CERT-In clock, steps and a draft, and email limits."""


def _attack_incident(api):
    return next(a["incident_id"] for a in api.get("/api/alerts").json() if a["id"] == "a-01")


def test_plan_confirm_steps_and_draft(api):
    inc = _attack_incident(api)
    p = api.get(f"/api/incidents/{inc}/respond").json()
    assert p["confirmed_at"] is None and p["cert_in_deadline"] is None
    who = {n["who"] for n in p["notify"]}
    assert "intern_a" in who
    assert any(s["text"].startswith("Isolate laptop-42") for s in p["steps"])
    p = api.post(f"/api/incidents/{inc}/confirm").json()
    assert p["confirmed_at"] and p["cert_in_deadline"] > p["confirmed_at"]
    step = p["steps"][0]["id"]
    p = api.post(f"/api/incidents/{inc}/steps", json={"step": step}).json()
    assert p["steps"][0]["requested_at"]
    draft = api.get(f"/api/incidents/{inc}/cert-in").json()["markdown"]
    assert "How it started: Phishing" in draft and "Actions taken" in draft


def test_email_needs_setup_and_listed_contacts(api, monkeypatch):
    inc = _attack_incident(api)
    monkeypatch.delenv("SMTP_USER", raising=False)
    assert api.post(f"/api/incidents/{inc}/notify", json={"to": ["Someone"]}).status_code == 503
    monkeypatch.setenv("SMTP_USER", "x@example.com")
    monkeypatch.setenv("SMTP_APP_PASSWORD", "x")
    monkeypatch.setenv("NOTIFY_CONTACTS", '[{"name": "Vatanesh", "email": "v@example.com"}]')
    r = api.post(f"/api/incidents/{inc}/notify", json={"to": ["Not listed"]})
    assert r.status_code == 422
