"""the hosted site runs on neo4j auradb free, which has no graph data science. every analysis must fall back to
python there, using only the packages the hosted site installs. these tests use a neo4j without the plugin."""
import pytest
from testcontainers.community.neo4j import Neo4jContainer

from app import evaluate_all, scenarios
from app.analysis import run_all
from app.scoring import score_all
from app.seed import load

IMAGE = "neo4j:2026.09.0"


@pytest.fixture(scope="module")
def plain_driver():
    with Neo4jContainer(IMAGE, password="test-password") as c:
        driver = c.get_driver()
        yield driver
        driver.close()


def test_analysis_runs_without_gds(plain_driver, attack_ids):
    with plain_driver.session() as s:
        load(s)
        run_all(s)
        score_all(s)
        danger = s.run("MATCH (n) WHERE n.danger IS NOT NULL RETURN count(n) AS c").single()["c"]
        top5 = [r["id"] for r in s.run("MATCH (a:Alert) RETURN a.id AS id ORDER BY a.score DESC, a.time LIMIT 5")]
    assert danger > 0
    assert attack_ids <= set(top5)


def test_every_scenario_evaluates_without_gds(plain_driver):
    with plain_driver.session() as s:
        results = evaluate_all.run(s)
    assert [r["scenario"] for r in results] == [c["id"] for c in scenarios.catalog()]
    for r in results:
        assert r["attack"] > 0 and r["graphops"]["last_attack_rank"] is not None
