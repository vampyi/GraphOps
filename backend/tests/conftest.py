import json

import pytest
from testcontainers.community.neo4j import Neo4jContainer

from app import seed
from app.analysis import run_all
from app.db import ROOT
from app.scoring import score_all

IMAGE = "neo4j:2026.09.0"


@pytest.fixture(scope="session")
def neo4j_driver():
    container = (
        Neo4jContainer(IMAGE, password="test-password")
        .with_env("NEO4J_PLUGINS", '["apoc", "graph-data-science"]')
        .with_env("NEO4J_dbms_security_procedures_unrestricted", "apoc.*,gds.*")
    )
    with container as c:
        driver = c.get_driver()
        yield driver
        driver.close()


@pytest.fixture()
def seeded(neo4j_driver):
    """freshly seeded sample data for each test that needs it."""
    with neo4j_driver.session() as s:
        counts = seed.load(s)
        run_all(s)
        score_all(s)
    return counts


@pytest.fixture(scope="session")
def attack_ids():
    alerts = json.loads((ROOT / "data" / "sample_org" / "alerts.json").read_text())["alerts"]
    return {a["id"] for a in alerts if a["scenario"] == "attack"}


@pytest.fixture()
def api(neo4j_driver, seeded):
    from fastapi.testclient import TestClient
    from app import main
    main._driver = neo4j_driver
    return TestClient(main.app)
