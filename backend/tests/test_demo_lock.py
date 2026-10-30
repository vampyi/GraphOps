"""the shared demo database lets one visitor reload it at a time, and the lock survives the reload itself."""
from app import scenarios, seed


def test_one_reload_at_a_time(neo4j_driver):
    with neo4j_driver.session() as s:
        scenarios.release(s)
        assert scenarios.acquire(s, "loading a")
        assert not scenarios.acquire(s, "loading b")
        assert scenarios.busy(s) == "loading a"
        seed.load_network(s)  # a reload wipes the graph but not the lock
        assert not scenarios.acquire(s, "loading b")
        scenarios.release(s)
        assert scenarios.busy(s) is None
        assert scenarios.acquire(s, "loading b")
        scenarios.release(s)
