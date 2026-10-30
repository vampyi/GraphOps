"""the real apt29 lab day: it brings its own network, its alerts load on real machines, and the sample org is back after."""
from app import scenarios, seed, simulate


def test_apt29_day_loads_its_own_network(neo4j_driver):
    with neo4j_driver.session() as s:
        try:
            out = scenarios.load_scenario(s, "apt29_day1")
            assert out["counts"]["nodes"] == 5 and len(out["attack_ids"]) == 16
            assert s.run("MATCH (c:Computer {id: 'newyork', critical: true}) RETURN count(c) AS n").single()["n"] == 1
            assert s.run("MATCH (n {id: 'laptop-42'}) RETURN count(n) AS n").single()["n"] == 0
            first = s.run("MATCH (a:Alert {id: 'apt-01'})-[:Involves]->(e) RETURN collect(e.id) AS ids").single()["ids"]
            assert set(first) == {"scranton", "pbeesly"}
        finally:
            seed.load(s)


def test_apt29_streams_without_inventing_background():
    day = simulate.build(attack=True, day_path=scenarios._path_for("apt29_day1"))
    assert {topic for topic, _, _ in day} <= {"cmdb", "alerts", "identity"}
    assert sum(1 for topic, _, _ in day if topic == "alerts") == 38
