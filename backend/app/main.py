"""backend server: the api the dashboard calls."""
import datetime as dt
import logging
import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import access, exposure, ingest, simulate, stream
from .attack import GRANTED_EDGES, USED_EDGES, tag
from .communities import summary as community_summary
from .db import ROOT, driver
from .report import incident_report
from .scoring import WEIGHTS, score_all
from .story import write_story

app = FastAPI(title="GraphOps")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
_driver = driver()

# the edges an attacker follows, as one pipe-separated string for cypher. one source: app/attack.py.
ATTACK_EDGES = "MemberOf|AdminTo|CanRDP|GenericAll|HasSession|RemoteLogon"
BLAST_EDGES = {"all": ATTACK_EDGES, "granted": "|".join(GRANTED_EDGES), "used": "|".join(USED_EDGES)}


@app.get("/api/alerts")
def alerts():
    with _driver.session() as s:
        return _alert_rows(s)


def _alert_rows(s, since=None):
    return _with_breakdown([dict(r) for r in s.run(
        """
        MATCH (a:Alert) WHERE $since IS NULL OR coalesce(a.changed_seq, 0) > $since
        OPTIONAL MATCH (a)-[:Involves]->(e)
        WITH a, collect(e.id) AS involves
        RETURN a.id AS id, a.time AS time, a.name AS name, a.severity AS severity,
               a.score AS score, a.reasons AS reasons, a.incident_id AS incident_id,
               a.tactic_id AS tactic_id, a.technique_id AS technique_id, a.status AS status,
               a.source_tool AS source_tool, involves,
               {hops: a.f_hops, blast: a.f_blast, linked: a.f_linked, never_taken: a.f_never_taken,
                stages: a.f_stages, choke: a.f_choke, severity: a.f_severity} AS features
        ORDER BY a.score DESC, a.time
        """, since=since)])


def _with_breakdown(rows):
    """points each ranking question added to the score, so the dashboard can draw them as bars."""
    for r in rows:
        f = r.pop("features") or {}
        r["breakdown"] = {k: round(WEIGHTS[k] * (f.get(k) or 0), 1) for k in WEIGHTS}
    return rows


@app.get("/api/alerts/{alert_id}/blast-radius")
def blast_radius(alert_id: str, mode: str = "all", days: int = access.DEFAULT_DAYS):
    """everything reachable from the alert's machines and users in 1, 2 and 3 steps. mode picks the edges:
    all attack edges, only granted permissions, or only logons actually used in the last `days` days. the two
    circles for granted and used are how we show the risk that least privilege removes."""
    if mode not in BLAST_EDGES:
        raise HTTPException(422, "mode must be 'all', 'granted' or 'used'")
    rel = BLAST_EDGES[mode]
    window = access.since(days) if mode == "used" else None
    with _driver.session() as s:
        if not s.run("MATCH (a:Alert {id: $id}) RETURN a", id=alert_id).single():
            raise HTTPException(404, "alert not found")
        rings = [dict(r) for r in s.run(
            f"""
            MATCH (a:Alert {{id: $id}})-[:Involves]->(start)
            MATCH p = (start)-[:{rel}*1..3]->(n)
            WHERE NOT n.id IN [x IN nodes(p)[..-1] | x.id]
              AND ($win IS NULL OR all(r IN relationships(p) WHERE coalesce(r.last_seen, $win) >= $win))
            WITH n, min(length(p)) AS hop
            RETURN n.id AS id, labels(n)[0] AS kind, coalesce(n.critical, false) AS critical, hop
            ORDER BY hop, id
            """, id=alert_id, win=window)]
        starts = [dict(r) for r in s.run(
            "MATCH (:Alert {id: $id})-[:Involves]->(e) RETURN e.id AS id, labels(e)[0] AS kind, coalesce(e.critical, false) AS critical, 0 AS hop",
            id=alert_id)]
        start_ids = {x["id"] for x in starts}
        nodes = starts + [r for r in rings if r["id"] not in start_ids]
        ids = [n["id"] for n in nodes]
        edges = [dict(r) for r in s.run(
            f"""
            MATCH (x)-[r:{rel}]->(y) WHERE x.id IN $ids AND y.id IN $ids
              AND ($win IS NULL OR coalesce(r.last_seen, $win) >= $win)
            RETURN x.id AS src, type(r) AS type, y.id AS dst
            """, ids=ids, win=window)]
        details = {r["id"]: r for r in (dict(x) for x in s.run(
            """
            MATCH (n) WHERE n.id IN $ids
            RETURN n.id AS id, n.name AS name, n.zone AS zone, n.os AS os, n.owner AS owner,
                   n.community AS community,
                   n.hops_to_critical AS hops_to_critical, n.critical_within_3 AS critical_within_3,
                   round(coalesce(n.choke_score, 0), 2) AS choke_score
            """, ids=ids))}
        for n in nodes:
            n.update({k: v for k, v in details.get(n["id"], {}).items() if k != "id"})
        attack_path = None
        if mode == "all":
            path = s.run(
                f"""
                MATCH (:Alert {{id: $id}})-[:Involves]->(start)
                MATCH (c) WHERE c.critical = true AND c <> start
                MATCH p = shortestPath((start)-[:{rel}*..6]->(c))
                RETURN [x IN nodes(p) | x.id] AS ids, [r IN relationships(p) | type(r)] AS types
                ORDER BY length(p) LIMIT 1
                """, id=alert_id).single()
            if path:
                attack_path = {"nodes": path["ids"], "types": path["types"],
                               "tags": [tag(t) for t in path["types"]]}
        counts = {"reachable": len([n for n in nodes if n["hop"] > 0]),
                  "critical": len([n for n in nodes if n["hop"] > 0 and n["critical"]])}
        return {"alert_id": alert_id, "mode": mode, "nodes": nodes, "edges": edges,
                "attack_path": attack_path, "counts": counts}


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):
    with _driver.session() as s:
        meta = s.run(
            """
            MATCH (i:Incident {id: $id})
            RETURN i.status AS status, i.notes AS notes, i.opened_at AS opened_at,
                   i.communities AS communities, i.lateral AS lateral, i.stages AS stages, i.score AS score
            """, id=incident_id).single()
        rows = [dict(r) for r in s.run(
            """
            MATCH (a:Alert {incident_id: $id})
            RETURN a.id AS id, a.time AS time, a.name AS name, a.tactic_id AS tactic_id,
                   a.technique_id AS technique_id, a.score AS score, a.status AS status
            ORDER BY a.time
            """, id=incident_id)]
        if not rows:
            raise HTTPException(404, "incident not found")
        out = {"id": incident_id, "alerts": rows}
        if meta:
            out.update({k: meta[k] for k in ("status", "notes", "opened_at", "communities", "lateral", "stages", "score")})
        return out


@app.post("/api/incidents/{incident_id}/story")
def story(incident_id: str):
    with _driver.session() as s:
        result = write_story(s, incident_id)
        if result is None:
            raise HTTPException(404, "incident not found")
        return result


@app.get("/api/incidents/{incident_id}/report")
def report(incident_id: str):
    """a containment-ready incident report in markdown: summary, attack timeline in stage order, affected and
    reachable assets, the choke points on the path and the analyst's notes. shaped around what CERT-In's 6-hour
    report asks for."""
    with _driver.session() as s:
        result = incident_report(s, incident_id)
        if result is None:
            raise HTTPException(404, "incident not found")
        return result


class IncidentPatch(BaseModel):
    status: str | None = None
    notes: str | None = None


@app.patch("/api/incidents/{incident_id}")
def patch_incident(incident_id: str, body: IncidentPatch):
    """set an incident's status or notes. both survive re-scoring because scoring carries them over by the
    alerts an incident shares with its previous self."""
    allowed = ("open", "investigating", "contained", "closed")
    if body.status is not None and body.status not in allowed:
        raise HTTPException(422, f"status must be one of {', '.join(allowed)}")
    with _driver.session() as s:
        r = s.run(
            """
            MATCH (i:Incident {id: $id})
            SET i.status = coalesce($status, i.status), i.notes = coalesce($notes, i.notes)
            RETURN i.status AS status, i.notes AS notes
            """, id=incident_id, status=body.status, notes=body.notes).single()
        if not r:
            raise HTTPException(404, "incident not found")
        return {"id": incident_id, "status": r["status"], "notes": r["notes"]}


class Verdict(BaseModel):
    status: str
    by: str | None = None


@app.post("/api/alerts/{alert_id}/verdict")
def verdict(alert_id: str, body: Verdict):
    """the analyst's call on an alert. 'benign' records real-but-allowed activity (a benign positive), which a
    real/false-only choice cannot hold. who and when are stored so verdicts can later train a ranking model."""
    if body.status not in ("real", "benign", "false"):
        raise HTTPException(422, "status must be 'real', 'benign' or 'false'")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    with _driver.session() as s:
        r = s.run(
            """
            MATCH (a:Alert {id: $id})
            SET a.status = $st, a.verdict_by = $by, a.verdict_at = $at
            RETURN a.status AS status, a.verdict_by AS by, a.verdict_at AS at
            """, id=alert_id, st=body.status, by=body.by, at=now).single()
        if not r:
            raise HTTPException(404, "alert not found")
        return {"id": alert_id, "status": r["status"], "by": r["by"], "at": r["at"]}


@app.get("/api/exposure")
def get_exposure(scope: str = "low_trust", max_hops: int = exposure.MAX_HOPS):
    """attack paths from the chosen starting zone to critical assets, the choke points they share and the
    fixes that cut the most paths. scope 'low_trust' starts from low-trust machines, 'all' from every
    non-critical identity and machine."""
    if scope not in exposure.SCOPES:
        raise HTTPException(422, f"scope must be one of {', '.join(exposure.SCOPES)}")
    if not 1 <= max_hops <= 10:
        raise HTTPException(422, "max_hops must be between 1 and 10")
    with _driver.session() as s:
        return exposure.analyse(s, scope, max_hops)


class Removal(BaseModel):
    scope: str = "low_trust"
    nodes: list[str] = []
    edges: list[dict] = []
    max_hops: int = exposure.MAX_HOPS


@app.post("/api/exposure/simulate")
def post_exposure_simulate(body: Removal):
    """recompute reachability after removing chosen nodes or edges and report, exactly, how many source-to-
    critical pairs and paths are cut. edges are {src, type, dst}; a missing type removes every edge between the
    pair. nothing in the database changes."""
    if body.scope not in exposure.SCOPES:
        raise HTTPException(422, f"scope must be one of {', '.join(exposure.SCOPES)}")
    for e in body.edges:
        if "src" not in e or "dst" not in e:
            raise HTTPException(422, "each edge needs at least src and dst")
    with _driver.session() as s:
        return exposure.simulate_on(s, body.scope, body.nodes, body.edges, body.max_hops)


@app.get("/api/entities/{entity_id}/access")
def entity_access(entity_id: str, days: int = access.DEFAULT_DAYS):
    """one identity's granted reach, its used reach over the last `days` days, and the grants it never uses."""
    with _driver.session() as s:
        result = access.compare(s, entity_id, days)
        if result is None:
            raise HTTPException(404, "entity not found")
        return result


@app.get("/api/access/overview")
def access_overview(days: int = access.DEFAULT_DAYS):
    """every user account ranked by the access it holds but has not used in the last `days` days."""
    with _driver.session() as s:
        return access.overview(s, days)


@app.get("/api/communities")
def communities():
    """the activity communities and their members, for labelling the graph and spotting cross-group movement."""
    with _driver.session() as s:
        return {"communities": community_summary(s)}


class AssetPatch(BaseModel):
    critical: bool | None = None
    zone: str | None = None


@app.patch("/api/assets/{asset_id}")
def patch_asset(asset_id: str, body: AssetPatch):
    """mark an asset critical or set its zone, then re-run the analysis and scoring so every distance, choke
    point and alert score reflects the change. this is how an analyst tells GraphOps what matters."""
    if body.zone is not None and body.zone not in ("low_trust", "normal"):
        raise HTTPException(422, "zone must be 'low_trust' or 'normal'")
    with _driver.session() as s:
        r = s.run(
            """
            MATCH (n {id: $id}) WHERE n:User OR n:Group OR n:Computer
            SET n.critical = coalesce($critical, n.critical), n.zone = coalesce($zone, n.zone)
            RETURN n.id AS id, labels(n)[0] AS kind, coalesce(n.critical, false) AS critical, n.zone AS zone
            """, id=asset_id, critical=body.critical, zone=body.zone).single()
        if not r:
            raise HTTPException(404, "asset not found")
        _reanalyse(s)
        return {"id": r["id"], "kind": r["kind"], "critical": r["critical"], "zone": r["zone"]}


def _reanalyse(s):
    from .analysis import run_all
    run_all(s)
    score_all(s)
    seq = (s.run("MATCH (st:StreamState {id: 'live'}) RETURN st.seq AS seq").single() or {"seq": 0})["seq"]
    s.run("MATCH (a:Alert) SET a.changed_seq = $seq", seq=(seq or 0) + 1)
    s.run("MERGE (st:StreamState {id: 'live'}) SET st.seq = $seq", seq=(seq or 0) + 1)


class IngestEvents(BaseModel):
    events: list[dict]


@app.post("/api/ingest")
def post_ingest(body: IngestEvents):
    """accept a batch of events already in the streaming schema (the same shape Kafka carries), write them to
    the graph once each and re-score. this is the door for a tool that posts straight to GraphOps."""
    with _driver.session() as s:
        result = ingest.ingest_events(s, body.events)
        return result


class IngestAlerts(BaseModel):
    format: str | None = None
    alerts: list[dict]


@app.post("/api/ingest/alerts")
def post_ingest_alerts(body: IngestAlerts, format: str | None = None):
    """accept alerts shaped like a named SIEM or EDR product, map them into GraphOps alert events and ingest
    them. hosts and accounts named by an alert that are not in the graph yet are created, so the picture grows
    from telemetry. format can be given in the query or the body."""
    fmt = format or body.format or "graphops"
    if fmt not in ingest.ALERT_FORMATS:
        raise HTTPException(422, f"format must be one of {', '.join(ingest.ALERT_FORMATS)}")
    with _driver.session() as s:
        try:
            events = ingest.map_alerts(body.alerts, fmt)
        except ingest.MappingError as exc:
            raise HTTPException(422, str(exc))
        result = ingest.ingest_events(s, events)
        result["format"] = fmt
        return result


# live replay. with KAFKA_BOOTSTRAP set, the simulator sends to kafka and /api/live reads it back.
# without it, the simulator writes straight into neo4j, so the live view still works with no broker.
_KAFKA = stream.kafka_config()
_consumer = None
_consumer_lock = threading.Lock()
_replay = {"thread": None, "stop": threading.Event()}
log = logging.getLogger("graphops.api")


def _get_consumer():
    global _consumer
    if _consumer is None:
        _consumer = stream.consumer(_KAFKA)
    return _consumer


class Replay(BaseModel):
    attack: bool = False
    speed: float = 60


@app.post("/api/replay/reset")
def replay_reset():
    """stop any replay and start a fresh day: the network only, no alerts yet."""
    _stop_replay()
    with _driver.session() as s:
        if _KAFKA:
            with _consumer_lock:
                stream.reset(s, _get_consumer())
        else:
            stream.reset(s)
    return {"status": "reset", "mode": "kafka" if _KAFKA else "direct"}


@app.post("/api/replay/start")
def replay_start(body: Replay):
    if not 0 <= body.speed <= 10_000:
        raise HTTPException(422, "speed must be between 0 and 10000")
    if _replay["thread"] and _replay["thread"].is_alive():
        raise HTTPException(409, "a replay is already running")
    day = simulate.build(attack=body.attack)
    _replay["stop"] = stop = threading.Event()

    def run():
        try:
            if _KAFKA:
                prod = stream.producer(_KAFKA)
                stream.create_topics(_KAFKA)
                simulate.play(day, simulate.kafka_sender(prod), speed=body.speed, stop=stop)
                prod.flush(30)
            else:
                with _driver.session() as s:
                    simulate.play(day, lambda topic, key, msg: stream.write_direct(s, topic, msg), speed=body.speed, stop=stop)
        except Exception:
            log.exception("replay failed")

    # vercel freezes a function once it has answered, so there the replay runs inside the request
    if os.environ.get("VERCEL"):
        run()
        return {"status": "finished", "messages": len(day)}
    _replay["thread"] = threading.Thread(target=run, daemon=True)
    _replay["thread"].start()
    return {"status": "started", "messages": len(day), "mode": "kafka" if _KAFKA else "direct"}


def _stop_replay():
    _replay["stop"].set()
    if _replay["thread"]:
        _replay["thread"].join(timeout=5)


@app.get("/api/live")
def live(since: int = 0):
    """read whatever is new, update the graph and return alerts that are new or changed since `since`."""
    with _driver.session() as s:
        ingested = 0
        if _KAFKA and _consumer_lock.acquire(blocking=False):
            # only one reader at a time per server. a call that finds it busy just returns what is saved.
            try:
                ingested = stream.ingest_once(s, _get_consumer())["events"]
            finally:
                _consumer_lock.release()
        else:
            stream.rescore(s)
        state = s.run("MATCH (st:StreamState {id: 'live'}) RETURN st.seq AS seq").single()
        seq = state["seq"] if state else 0
        running = bool(_replay["thread"] and _replay["thread"].is_alive())
        return {"seq": seq, "ingested": ingested, "replaying": running,
                "alerts": _alert_rows(s, since) if seq > since else []}


# serve the built dashboard from the same server when it exists (used on vercel and in production)
_DIST = ROOT / "frontend" / "dist"
if _DIST.is_dir():
    app.frontend("/", directory=str(_DIST))
