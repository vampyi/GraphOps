"""the real apt29 lab day with public sigma rules: the replay streams the lab's own activity, every message is valid,
labels never reach the ranker, and every alert keeps its rule's author as the detection rule licence asks."""
import json
import re
from pathlib import Path

from app import events, scenarios, seed, simulate, stream

DAY = scenarios._path_for("apt29_day1_sigma")


def _day():
    return json.loads(Path(DAY).read_text())


def test_sigma_day_streams_the_lab_activity_through_every_topic():
    day = simulate.build(attack=True, day_path=DAY)
    kinds = {msg["kind"] for _, _, msg in day}
    assert {"Asset", "RemoteLogon", "LoggedInto", "ProcessStart", "Connection", "Alert"} <= kinds
    for topic, _, msg in day:
        events.parse(json.dumps(msg).encode(), topic)  # raises on anything the live reader would reject
        assert "scenario" not in msg  # the attack labels are for scoring the ranking only
    assert len({msg["event_id"] for _, _, msg in day}) == len(day)
    assert sum(1 for topic, _, _ in day if topic == "alerts") == len(_day()["alerts"])


def test_sigma_day_without_the_attack_keeps_only_background():
    doc = _day()
    day = simulate.build(attack=False, day_path=DAY)
    alerts = [msg for topic, _, msg in day if topic == "alerts"]
    assert len(alerts) == sum(1 for a in doc["alerts"] if a["scenario"] == "noise")
    assert len([1 for topic, _, _ in day if topic == "edr"]) == sum(1 for p in doc["process_starts"] if p["scenario"] == "noise")


def test_every_sigma_alert_keeps_its_rule_and_names_lab_machines():
    doc = _day()
    machines = {n["id"] for n in doc["network"]["nodes"] if n["label"] == "Computer"}
    release = doc["rules"]["release"]
    for a in doc["alerts"]:
        assert a["source_tool"] == "Sigma" and a["rule"] and a["rule_author"]
        assert a["rule_link"].startswith(f"https://github.com/SigmaHQ/sigma/blob/{release}/rules/windows/")
        assert a["involves"][0] in machines
        assert a["severity"] in ("low", "medium", "high", "critical")
        # command-line passwords are removed (psexec -p, rar -hp)
        assert not re.search(r"\s-p\s+(?!\[removed\])\S", a["evidence"]) and not re.search(r"\s-hp(?!\[removed\])\S", a["evidence"])


def test_sigma_day_loads_its_own_network_and_alerts(neo4j_driver):
    with neo4j_driver.session() as s:
        try:
            out = scenarios.load_scenario(s, "apt29_day1_sigma")
            assert out["counts"]["nodes"] == 5
            assert len(out["attack_ids"]) == sum(1 for a in _day()["alerts"] if a["scenario"] == "attack")
            n = s.run("MATCH (a:Alert) WHERE a.rule_author IS NOT NULL RETURN count(a) AS n").single()["n"]
            assert n == len(_day()["alerts"])
        finally:
            seed.load(s)


def test_sigma_day_replays_real_logons_into_the_graph(neo4j_driver):
    doc = _day()
    with neo4j_driver.session() as s:
        try:
            stream.reset(s, network=doc["network"])
            simulate.play(simulate.build(attack=True, day_path=DAY), lambda t, k, m: stream.write_direct(s, t, m), speed=0)
            first = min(e["time"] for e in doc["events"]
                        if (e["src"], e["type"], e["dst"]) == ("scranton", "RemoteLogon", "nashua"))
            row = s.run("MATCH (:Computer {id: 'scranton'})-[r:RemoteLogon]->(:Computer {id: 'nashua'}) "
                        "RETURN r.first_seen AS f").single()
            assert row["f"] == first  # the lateral movement route appears at its real time
            n = s.run("MATCH (a:Alert) WHERE a.rule_author IS NOT NULL RETURN count(a) AS n").single()["n"]
            assert n == len(doc["alerts"])  # the live path keeps each rule's author too
        finally:
            seed.load(s)
