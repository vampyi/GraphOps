"""tests for the live flow in docs/streaming.md, run against a real kafka and neo4j in containers."""
import json
import socket
import time

import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy

from app import events, seed, simulate, stream
from app.analysis import run_all
from app.scoring import score_all

KAFKA_IMAGE = "apache/kafka:4.3.1"


def _free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def kafka_conf():
    port = _free_port()
    container = (
        DockerContainer(KAFKA_IMAGE)
        .with_bind_ports(9092, port)
        .with_env("KAFKA_NODE_ID", "1")
        .with_env("KAFKA_PROCESS_ROLES", "broker,controller")
        .with_env("KAFKA_LISTENERS", "PLAINTEXT://:9092,CONTROLLER://:9093")
        .with_env("KAFKA_ADVERTISED_LISTENERS", f"PLAINTEXT://localhost:{port}")
        .with_env("KAFKA_CONTROLLER_LISTENER_NAMES", "CONTROLLER")
        .with_env("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT")
        .with_env("KAFKA_CONTROLLER_QUORUM_VOTERS", "1@localhost:9093")
        .with_env("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR", "1")
        .with_env("KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR", "1")
        .with_env("KAFKA_TRANSACTION_STATE_LOG_MIN_ISR", "1")
        .waiting_for(LogMessageWaitStrategy("Kafka Server started").with_startup_timeout(90))
    )
    with container:
        conf = {"bootstrap.servers": f"localhost:{port}"}
        stream.create_topics(conf)
        yield conf


@pytest.fixture()
def live(neo4j_driver, kafka_conf):
    """a fresh live day: network only, read positions at the end of every topic."""
    cons = stream.consumer(kafka_conf)
    with neo4j_driver.session() as s:
        stream.reset(s, cons)
    yield cons
    cons.close()


def send_all(conf, day, twice=False):
    prod = stream.producer(conf)
    send = simulate.kafka_sender(prod)
    simulate.play(day, send, speed=0)
    if twice:
        simulate.play(day, send, speed=0)
    prod.flush(30)


def drain(session, cons, limit=stream.BATCH):
    total = {"events": 0, "skipped": 0, "bad": 0}
    for _ in range(50):
        r = stream.ingest_once(session, cons, limit=limit)
        for k in total:
            total[k] += r[k]
        if not (r["events"] or r["skipped"] or r["bad"]):
            break
    return total


def results(session):
    return {r["id"]: (r["score"], r["inc"], r["reasons"]) for r in session.run(
        "MATCH (a:Alert) RETURN a.id AS id, a.score AS score, a.incident_id AS inc, a.reasons AS reasons")}


@pytest.fixture(scope="module")
def batch_result(neo4j_driver):
    """what the first flow's one-batch load gives, to compare the live flow against."""
    with neo4j_driver.session() as s:
        seed.load(s)
        run_all(s)
        score_all(s)
        return results(s)


def test_attack_replay_through_kafka_matches_batch(neo4j_driver, kafka_conf, live, batch_result, attack_ids):
    send_all(kafka_conf, simulate.build(attack=True))
    with neo4j_driver.session() as s:
        counts = drain(s, live)
        got = results(s)
    assert counts["events"] == len(simulate.build(attack=True))
    assert got == batch_result
    top5 = sorted(got, key=lambda k: -got[k][0])[:5]
    assert attack_ids <= set(top5)
    assert len({got[a][1] for a in attack_ids}) == 1


def test_day_without_attack_has_no_attack_alerts(neo4j_driver, kafka_conf, live, attack_ids):
    send_all(kafka_conf, simulate.build(attack=False))
    with neo4j_driver.session() as s:
        drain(s, live)
        got = results(s)
    assert len(got) == 26 and not attack_ids & set(got)


def test_duplicates_change_nothing(neo4j_driver, kafka_conf, live, batch_result):
    day = simulate.build(attack=True)
    send_all(kafka_conf, day, twice=True)
    with neo4j_driver.session() as s:
        counts = drain(s, live)
        got = results(s)
        logons = s.run("MATCH (:Computer {id: 'laptop-42'})-[r:RemoteLogon]->(:Computer {id: 'server-7'}) RETURN r.count AS c").single()["c"]
    assert counts["events"] == len(day) and counts["skipped"] == len(day)
    assert got == batch_result
    assert logons == 1


def test_crash_halfway_loses_and_repeats_nothing(neo4j_driver, kafka_conf, live, batch_result, monkeypatch):
    send_all(kafka_conf, simulate.build(attack=True))
    real_apply, calls = events.apply, {"n": 0}

    def crashing_apply(tx, event):
        calls["n"] += 1
        if calls["n"] == 120:
            raise RuntimeError("power cut")
        return real_apply(tx, event)

    monkeypatch.setattr(stream, "apply", crashing_apply)
    with neo4j_driver.session() as s:
        with pytest.raises(RuntimeError):
            drain(s, live)
        assert s.run("MATCH (e:Event) RETURN count(e) AS c").single()["c"] == 0
        monkeypatch.setattr(stream, "apply", real_apply)
        drain(s, live)
        assert results(s) == batch_result
        assert s.run("MATCH (e:Event) RETURN count(e) AS c").single()["c"] == len(simulate.build(attack=True))


def test_alert_shows_in_live_api_within_5_seconds(neo4j_driver, kafka_conf, live, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    monkeypatch.setattr(main, "_driver", neo4j_driver)
    monkeypatch.setattr(main, "_KAFKA", kafka_conf)
    monkeypatch.setattr(main, "_consumer", None)
    api = TestClient(main.app)
    alert = next(m for t, k, m in simulate.build(attack=True) if m["event_id"] == "al-a-01")

    prod = stream.producer(kafka_conf)
    sent = time.monotonic()
    prod.produce("alerts", key=b"laptop-42", value=json.dumps(alert).encode())
    prod.flush(10)
    seen = None
    while time.monotonic() - sent < 5:
        body = api.get("/api/live", params={"since": 0}).json()
        if any(a["id"] == "a-01" for a in body["alerts"]):
            seen = time.monotonic() - sent
            break
        time.sleep(0.2)
    main._consumer.close()
    assert seen is not None and seen < 5
    assert body["alerts"][0]["score"] is not None


def test_bad_messages_are_skipped(neo4j_driver, kafka_conf, live):
    good = next(m for t, k, m in simulate.build(attack=True) if m["event_id"] == "al-a-01")
    prod = stream.producer(kafka_conf)
    for value in [b"", b"x" * (events.MAX_BYTES + 1), b"{not json", b"[1, 2]",
                  json.dumps({"event_id": "z", "time": "t", "source_tool": "x", "kind": "Teleport"}).encode(),
                  json.dumps({**good, "event_id": "al-wrong-topic"}).encode()]:
        topic = "identity" if b"wrong-topic" in value else "alerts"
        prod.produce(topic, key=b"k", value=value)
    prod.produce("alerts", key=b"laptop-42", value=json.dumps(good).encode())
    prod.flush(10)
    with neo4j_driver.session() as s:
        counts = drain(s, live)
        assert s.run("MATCH (a:Alert) RETURN collect(a.id) AS ids").single()["ids"] == ["a-01"]
    assert counts == {"events": 1, "skipped": 0, "bad": 6}


def test_direct_mode_without_kafka_matches_batch(neo4j_driver, batch_result):
    with neo4j_driver.session() as s:
        stream.reset(s)
        simulate.play(simulate.build(attack=True), lambda t, k, m: stream.write_direct(s, t, m), speed=0)
        stream.rescore(s)
        assert results(s) == batch_result


def test_simulator_is_repeatable_and_valid():
    day = simulate.build(attack=True)
    assert day == simulate.build(attack=True)
    assert len({m["event_id"] for _, _, m in day}) == len(day)
    for topic, _, msg in day:
        events.parse(json.dumps(msg).encode(), topic)
    times = [m["time"] for _, _, m in day]
    assert times == sorted(times)
