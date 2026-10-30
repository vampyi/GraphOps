"""read new events from kafka, write them to neo4j and re-score the alerts.

we do not use kafka consumer groups: joining a group takes seconds, too slow for a short call every
2 seconds on vercel. instead we read each partition directly and save how far we have read (the offset)
in neo4j, in the same transaction as the events. a crash loses nothing and repeats nothing."""
import json
import logging
import os
import sys
import time

from .analysis import run_all
from .events import TOPICS, BadEvent, apply_batch, parse
from .scoring import score_all

log = logging.getLogger("graphops.stream")

BATCH = 500


def kafka_config():
    """connection settings from the environment. KAFKA_BOOTSTRAP is required; the rest are for hosted kafka
    such as aiven, which needs a username, password and its certificate authority."""
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP")
    if not bootstrap:
        return None
    conf = {"bootstrap.servers": bootstrap}
    if os.environ.get("KAFKA_USERNAME"):
        conf.update({
            "security.protocol": "SASL_SSL",
            "sasl.mechanisms": os.environ.get("KAFKA_SASL_MECHANISM", "SCRAM-SHA-256"),
            "sasl.username": os.environ["KAFKA_USERNAME"],
            "sasl.password": os.environ["KAFKA_PASSWORD"],
        })
        if os.environ.get("KAFKA_CA_PEM"):
            conf["ssl.ca.pem"] = os.environ["KAFKA_CA_PEM"]
    return conf


def consumer(conf):
    from confluent_kafka import Consumer
    # group.id is required by the client, but we never join the group or commit to it
    return Consumer({**conf, "group.id": "graphops-ingest", "enable.auto.commit": False,
                     "enable.partition.eof": True, "auto.offset.reset": "earliest"})


def producer(conf):
    from confluent_kafka import Producer
    return Producer({**conf, "linger.ms": 20, "enable.idempotence": True})


def create_topics(conf, partitions=2):
    """create the five topics if they do not exist yet. aiven's free plan allows 5 topics of 2 partitions."""
    from confluent_kafka.admin import AdminClient, NewTopic
    admin = AdminClient(conf)
    existing = admin.list_topics(timeout=10).topics
    new = [NewTopic(t, num_partitions=partitions, replication_factor=1) for t in TOPICS if t not in existing]
    for future in admin.create_topics(new).values() if new else []:
        future.result()


def saved_offsets(session):
    return {(r["topic"], r["partition"]): r["offset"] for r in session.run(
        "MATCH (o:StreamOffset) RETURN o.topic AS topic, o.partition AS partition, o.offset AS offset")}


def read_new(cons, offsets, limit=BATCH, timeout=5.0):
    """read up to `limit` messages that arrived after the saved offsets. returns the messages and the
    offsets to save once they are written. we read until kafka says each partition has no more
    (end of partition), which saves asking for every partition's end position first."""
    from confluent_kafka import OFFSET_BEGINNING, KafkaError, TopicPartition
    meta = cons.list_topics(timeout=timeout).topics
    parts = [TopicPartition(t, p, offsets.get((t, p), OFFSET_BEGINNING))
             for t in TOPICS if t in meta for p in meta[t].partitions]
    if not parts:
        return [], {}
    cons.assign(parts)
    msgs, done, deadline = [], set(), time.monotonic() + timeout
    while len(done) < len(parts) and len(msgs) < limit and time.monotonic() < deadline:
        m = cons.poll(0.2)
        if m is None:
            continue
        key = (m.topic(), m.partition())
        if m.error():
            if m.error().code() == KafkaError._PARTITION_EOF:
                done.add(key)
            else:
                log.warning("kafka error on %s: %s", key, m.error())
            continue
        msgs.append(m)
    cons.unassign()
    new_offsets = {}
    for m in msgs:
        new_offsets[(m.topic(), m.partition())] = m.offset() + 1
    return msgs, new_offsets


def write_batch(session, msgs, new_offsets):
    """write the events and the new offsets in one transaction. returns counts of what changed."""
    def work(tx):
        events, bad = [], 0
        for m in msgs:
            try:
                events.append(parse(m.value(), m.topic()))
            except BadEvent as exc:
                log.warning("bad message %s/%s@%s: %s", m.topic(), m.partition(), m.offset(), exc)
                bad += 1
        result = apply_batch(tx, events) if events else {"events": 0, "skipped": 0, "alerts": 0, "network": False}
        result["bad"] = bad
        if new_offsets:
            tx.run(
                """
                UNWIND $rows AS row
                MERGE (o:StreamOffset {topic: row.t, partition: row.p})
                SET o.offset = CASE WHEN o.offset IS NULL OR row.o > o.offset THEN row.o ELSE o.offset END
                """,
                rows=[{"t": t, "p": p, "o": o} for (t, p), o in new_offsets.items()])
        if result["alerts"] or result["network"]:
            # scoring runs after this transaction. mark it pending so a crash in between is caught up next time
            tx.run("MERGE (s:StreamState {id: 'live'}) SET s.rescore = true, s.network = coalesce(s.network, false) OR $n",
                   n=result["network"])
        return result
    return session.execute_write(work)


class _Local:
    """a message that did not come through kafka, shaped like one for write_batch."""
    def __init__(self, topic, value):
        self._topic, self._value = topic, value

    def topic(self):
        return self._topic

    def value(self):
        return self._value

    partition = offset = lambda self: -1


def write_direct(session, topic, msg):
    """the no-broker fallback: write one simulator message straight into neo4j."""
    return write_batch(session, [_Local(topic, json.dumps(msg).encode())], {})


def rescore(session):
    """re-run the analysis and scoring if a batch asked for it. alerts whose score or incident changed
    get a new change number, which the dashboard uses to fetch only what changed."""
    state = session.run("MATCH (s:StreamState {id: 'live'}) RETURN s.rescore AS r, s.network AS n, coalesce(s.seq, 0) AS seq").single()
    if not state or not state["r"]:
        return None
    if state["n"]:
        run_all(session)
    before = {r["id"]: (r["score"], r["inc"]) for r in session.run(
        "MATCH (a:Alert) RETURN a.id AS id, a.score AS score, a.incident_id AS inc")}
    score_all(session)
    after = {r["id"]: (r["score"], r["inc"]) for r in session.run(
        "MATCH (a:Alert) RETURN a.id AS id, a.score AS score, a.incident_id AS inc")}
    changed = [k for k, v in after.items() if before.get(k) != v]
    seq = state["seq"] + 1
    session.run("UNWIND $ids AS id MATCH (a:Alert {id: id}) SET a.changed_seq = $seq", ids=changed, seq=seq)
    session.run("MATCH (s:StreamState {id: 'live'}) SET s.rescore = false, s.network = false, s.seq = $seq", seq=seq)
    return changed


def ingest_once(session, cons, limit=BATCH):
    """one round: read what is new, write it, re-score. safe to call from many places at once."""
    msgs, new_offsets = read_new(cons, saved_offsets(session), limit=limit)
    result = write_batch(session, msgs, new_offsets) if msgs else {"events": 0, "skipped": 0, "bad": 0, "alerts": 0, "network": False}
    result["changed"] = rescore(session) or []
    return result


def skip_to_end(session, cons, timeout=5.0):
    """save the current end of every topic as our read position, so old messages are not replayed."""
    from confluent_kafka import TopicPartition
    meta = cons.list_topics(timeout=timeout).topics
    rows = []
    for topic in TOPICS:
        for p in meta[topic].partitions if topic in meta else []:
            _, high = cons.get_watermark_offsets(TopicPartition(topic, p), timeout=timeout)
            rows.append({"t": topic, "p": p, "o": high})
    session.run("MATCH (o:StreamOffset) DELETE o")
    session.run("UNWIND $rows AS row CREATE (:StreamOffset {topic: row.t, partition: row.p, offset: row.o})", rows=rows)


def reset(session, cons=None, network=None):
    """start a fresh live day: the network only, no alerts, and read positions at the end of every topic. network is
    the day's own network when it brings one (a real lab recording); otherwise the sample organisation."""
    from .seed import load_network
    load_network(session, network=network)
    run_all(session)
    session.run("CREATE (:StreamState {id: 'live', seq: 0, rescore: false, network: false})")
    if cons is not None:
        skip_to_end(session, cons)


if __name__ == "__main__":
    # long-running reader for a laptop: python -m app.stream
    from .db import driver
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    conf = kafka_config() or sys.exit("set KAFKA_BOOTSTRAP in .env, for example localhost:9092")
    cons = consumer(conf)
    with driver() as d, d.session() as s:
        while True:
            r = ingest_once(s, cons)
            if r["events"] or r["bad"] or r["changed"]:
                log.info("events %s, duplicates %s, bad %s, alerts re-scored %s",
                         r["events"], r["skipped"], r["bad"], len(r["changed"]))
            else:
                time.sleep(0.5)
