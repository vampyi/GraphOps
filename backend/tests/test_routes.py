"""guard against the dashboard calling an endpoint the server does not have (the cause of a 404 on a click),
and against the single-page app 404ing on a refresh or a deep link. no database needed."""
import os

import pytest

# importing app.main builds a driver, which needs a password even though these tests never open a connection
os.environ.setdefault("NEO4J_PASSWORD", "test-only")

from app import main  # noqa: E402
from app.db import ROOT  # noqa: E402

# every endpoint the dashboard calls, from frontend/src/api.js. keep in step with that file.
FRONTEND_ENDPOINTS = [
    ("GET", "/api/alerts"),
    ("GET", "/api/alerts/{alert_id}/blast-radius"),
    ("GET", "/api/incidents/{incident_id}"),
    ("GET", "/api/incidents/{incident_id}/report"),
    ("PATCH", "/api/incidents/{incident_id}"),
    ("POST", "/api/incidents/{incident_id}/story"),
    ("GET", "/api/languages"),
    ("POST", "/api/ask"),
    ("POST", "/api/alerts/{alert_id}/verdict"),
    ("PATCH", "/api/assets/{asset_id}"),
    ("GET", "/api/exposure"),
    ("POST", "/api/exposure/simulate"),
    ("GET", "/api/entities/{entity_id}/access"),
    ("GET", "/api/access/overview"),
    ("GET", "/api/communities"),
    ("GET", "/api/graph/algorithms"),
    ("GET", "/api/graph/reachability-proof"),
    ("GET", "/api/evaluation"),
    ("GET", "/api/learning"),
    ("GET", "/api/scenarios"),
    ("POST", "/api/scenarios/{scenario_id}/load"),
    ("GET", "/api/live"),
    ("POST", "/api/replay/reset"),
    ("POST", "/api/replay/start"),
]


def _registered():
    have = set()
    for r in main.app.routes:
        methods = getattr(r, "methods", None)
        if methods and getattr(r, "path", "").startswith("/api"):
            for m in methods - {"HEAD", "OPTIONS"}:
                have.add((m, r.path))
    return have


def test_every_dashboard_endpoint_is_registered():
    have = _registered()
    missing = [e for e in FRONTEND_ENDPOINTS if e not in have]
    assert not missing, f"the dashboard calls endpoints the server does not expose: {missing}"


def test_spa_fallback_serves_index_not_404():
    """a refresh or a shared link on /console (or any non-api path) must return the app, not a 404."""
    if not (ROOT / "frontend" / "dist" / "index.html").is_file():
        pytest.skip("dashboard is not built (frontend/dist missing); build it to run this check")
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    for path in ("/console", "/console/exposure", "/console/access"):
        r = client.get(path, headers={"accept": "text/html"})
        assert r.status_code == 200 and "<!doctype html" in r.text.lower(), f"{path} did not serve the app"
    # an unknown api path still 404s (so a genuinely missing endpoint is not masked)
    assert client.get("/api/not-a-real-endpoint").status_code == 404


def test_health_endpoint_registered():
    """ops and load balancers probe /api/health; it must exist and not be masked by the SPA fallback."""
    assert ("GET", "/api/health") in _registered()
