"""backend server: the api the dashboard calls."""
import datetime as dt
import logging
import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import access, evaluate, exposure, graphinfo, ingest, scenarios, simulate, stream
from .attack import ATTACK_EDGES as attack_edge_list, GRANTED_EDGES, USED_EDGES, tag
from .communities import summary as community_summary
from .db import ROOT, driver
from .report import incident_report
from .scoring import WEIGHTS, score_all
from .story import write_story
from .llm import LANGUAGES

app = FastAPI(title="GraphOps")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
_driver = driver()

# the edges an attacker follows, as one pipe-separated string for cypher. one source: app/attack.py.
ATTACK_EDGES = "|".join(attack_edge_list)
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
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
            RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, coalesce(n.critical, false) AS critical, hop
            ORDER BY hop, id
            """, id=alert_id, win=window)]
        starts = [dict(r) for r in s.run(
            "MATCH (:Alert {id: $id})-[:Involves]->(e) RETURN e.id AS id, [l IN labels(e) WHERE l <> 'Entity'][0] AS kind, coalesce(e.critical, false) AS critical, 0 AS hop",
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
            RETURN n.id AS id, n.name AS name, n.zone AS zone, n.os AS os, n.owner AS owner, n.location AS location,
                   coalesce(n.kev, false) AS kev, n.vulns AS vulns,
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
def story(incident_id: str, lang: str = "en-IN"):
    if lang not in LANGUAGES:
        raise HTTPException(422, f"lang must be one of {', '.join(LANGUAGES)}")
    with _driver.session() as s:
        result = write_story(s, incident_id, lang=lang)
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


@app.get("/api/graph/algorithms")
def graph_algorithms():
    """the Neo4j / GDS algorithms GraphOps runs, each mapped to the SOC question it answers, with a live number.
    this is the 'why a graph, why Neo4j' roster the dashboard shows."""
    with _driver.session() as s:
        return {"summary": graphinfo.summary(s), "algorithms": graphinfo.algorithms(s), "gds": graphinfo.has_gds(s)}


@app.get("/api/graph/full")
def graph_full():
    """the whole graph with each node's community, pagerank and choke-point score, and the data model counts."""
    with _driver.session() as s:
        return graphinfo.full_graph(s)


@app.get("/api/evaluation")
def evaluation():
    """does GraphOps rank the attack above the noise, and better than severity-only? measured on the loaded day
    against its (hidden-from-the-ranker) attack labels."""
    with _driver.session() as s:
        act = scenarios.active(s)
        result = evaluate.evaluate(s, act["attack_ids"])
        result["scenario"] = act["id"]
        return result


@app.get("/api/scenarios")
def list_scenarios():
    """the labelled days GraphOps can load: the sample day the weights are tuned on, plus held-out scenarios."""
    with _driver.session() as s:
        return {"active": scenarios.active(s)["id"], "scenarios": scenarios.catalog(), "busy": scenarios.busy(s)}


@app.post("/api/scenarios/{scenario_id}/load")
def load_scenario(scenario_id: str):
    """swap the whole console to a different labelled day, score it, and record its attack labels. this is how
    we show the ranking holds on a day it was never tuned on."""
    if scenarios._path_for(scenario_id) is None:
        raise HTTPException(404, "unknown scenario")
    with _driver.session() as s:
        if not scenarios.acquire(s, f"loading {scenario_id}"):
            raise HTTPException(409, "someone else is reloading the demo data; try again in a minute")
        try:
            return scenarios.load_scenario(s, scenario_id)
        finally:
            scenarios.release(s)


@app.get("/api/graph/reachability-proof")
def reachability_proof(src: str, dst: str = None):
    """answer 'can src reach dst?' as one timed Cypher traversal and show the same question written in SQL, to
    make concrete why this is a graph problem. dst defaults to the nearest critical asset."""
    with _driver.session() as s:
        if dst is None:
            row = s.run("MATCH (c) WHERE c.critical = true RETURN c.id AS id ORDER BY c.id LIMIT 1").single()
            dst = row["id"] if row else None
        if dst is None:
            raise HTTPException(404, "no critical asset to reach")
        result = graphinfo.reachability_proof(s, src, dst)
        if "error" in result:
            raise HTTPException(404, result["error"])
        return result


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
            MATCH (n {id: $id}) WHERE n:Entity
            SET n.critical = coalesce($critical, n.critical), n.zone = coalesce($zone, n.zone)
            RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, coalesce(n.critical, false) AS critical, n.zone AS zone
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
    scenario: str | None = None  # which labelled day to stream; the dashboard sends the one selected


@app.post("/api/replay/reset")
def replay_reset():
    """stop any replay and start a fresh day: the network only, no alerts yet."""
    _stop_replay()
    with _driver.session() as s:
        if not scenarios.acquire(s, "starting a live stream"):
            raise HTTPException(409, "someone else is reloading the demo data; try again in a minute")
        try:
            if _KAFKA:
                with _consumer_lock:
                    stream.reset(s, _get_consumer())
            else:
                stream.reset(s)
        except Exception:
            scenarios.release(s)
            raise
    return {"status": "reset", "mode": "kafka" if _KAFKA else "direct"}


@app.post("/api/replay/start")
def replay_start(body: Replay):
    if not 0 <= body.speed <= 10_000:
        raise HTTPException(422, "speed must be between 0 and 10000")
    if _replay["thread"] and _replay["thread"].is_alive():
        raise HTTPException(409, "a replay is already running")
    with _driver.session() as s:
        sid = body.scenario or scenarios.active(s)["id"]
        path = scenarios._path_for(sid)
        if path is None:
            raise HTTPException(404, "unknown scenario")
        # the reset before a stream wipes the graph, so record again which day is playing and its attack labels
        scenarios.mark_active(s, sid, scenarios._attack_ids(path))
    day = simulate.build(attack=body.attack, day_path=path)
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
        finally:
            with _driver.session() as s2:
                scenarios.release(s2)

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


class Question(BaseModel):
    question: str
    history: list[dict] = []
    lang: str = "en-IN"


@app.post("/api/ask")
def ask_question(body: Question):
    """the ask tab: a plain-language question answered by the llm from graphops' read-only lookups only."""
    from . import ask, llm
    if body.lang not in LANGUAGES:
        raise HTTPException(422, f"lang must be one of {', '.join(LANGUAGES)}")
    if not llm.available():
        raise HTTPException(503, "The Ask tab needs a Sarvam AI key (SARVAM_API_KEY) on the server.")
    try:
        return ask.answer(body.question, _ask_tools(), body.history, body.lang)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except llm.LLMError as exc:
        raise HTTPException(502, f"The AI service failed: {exc}")


def _ask_tools():
    """the read-only lookups the ask tab may use, trimmed so the llm sees the facts, not the drawing data."""
    def top_alerts(limit=8, severity=None):
        rows = [r for r in alerts() if not severity or r["severity"] == severity]
        keep = ("id", "name", "score", "severity", "time", "involves", "reasons", "incident_id", "status")
        return [{k: r[k] for k in keep} for r in rows[: max(1, min(int(limit), 15))]]

    def alert_details(alert_id):
        rows = alerts()
        by_sev = sorted(rows, key=lambda r: (-SEVERITY_ORDER.get(r["severity"], 0), r["time"]))
        for i, r in enumerate(rows):
            if r["id"] == alert_id:
                return {**r, "rank_graphops": i + 1, "rank_by_severity": [x["id"] for x in by_sev].index(alert_id) + 1,
                        "points_by_question": r.pop("breakdown")}
        raise ValueError(f"no alert {alert_id}")

    def blast(alert_id=None, entity_id=None):
        if alert_id:
            b = blast_radius(alert_id)
        elif entity_id:
            b = _entity_reach(entity_id)
        else:
            raise ValueError("give alert_id or entity_id")
        by_hop = {}
        for n in b["nodes"]:
            by_hop.setdefault(n["hop"], []).append({"id": n["id"], "kind": n["kind"], "critical": n["critical"]})
        return {"start": by_hop.pop(0, []), "reachable_by_hop": by_hop,
                "critical_reachable": [n["id"] for n in b["nodes"] if n["critical"] and n["hop"] > 0],
                "shortest_path_to_critical": b.get("attack_path")}

    def attack_paths():
        with _driver.session() as s:
            x = exposure.analyse(s)
        return {"pairs": x["pairs"],
                "paths": [{k: p.get(k) for k in ("source", "target", "nodes", "types", "hops")} for p in x["paths"][:6]],
                "choke_points": x["chokepoints"][:5],
                "fixes": [{k: f.get(k) for k in ("title", "edges", "nodes", "pairs_cut", "share_cut") if f.get(k) is not None}
                          for f in x["recommendations"][:3]]}

    def access_gap(entity_id=None):
        with _driver.session() as s:
            if entity_id:
                c = access.compare(s, entity_id)
                if c is None:
                    raise ValueError(f"no identity {entity_id}")
                return {"identity": entity_id, "summary": c["summary"], "unused": [u["id"] for u in c["unused"]],
                        "used": [u["id"] for u in c["used"]]}
            o = access.overview(s)
        return {"totals": o["totals"], "accounts": [{"id": i["id"], "summary": i["summary"], "unused": i["unused"]}
                                                    for i in o["identities"][:8]]}

    def find_entities(text):
        with _driver.session() as s:
            return [dict(r) for r in s.run(
                """
                MATCH (n) WHERE n:Entity
                  AND (toLower(n.id) CONTAINS toLower($t) OR toLower(coalesce(n.name, '')) CONTAINS toLower($t)
                       OR toLower(coalesce(n.owner, '')) CONTAINS toLower($t))
                RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, n.name AS name, n.owner AS owner, coalesce(n.critical, false) AS critical
                LIMIT 10
                """, t=str(text)[:60])]

    return {"top_alerts": top_alerts, "alert_details": alert_details, "blast_radius": blast,
            "incident": incident, "attack_paths": attack_paths, "access_gap": access_gap,
            "ranking_quality": evaluation, "find_entities": find_entities}


def _entity_reach(entity_id):
    """blast radius from one user, group or machine (the alert version starts from an alert's entities)."""
    with _driver.session() as s:
        start = s.run("MATCH (n {id: $id}) WHERE n:Entity "
                      "RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, coalesce(n.critical, false) AS critical", id=entity_id).single()
        if not start:
            raise ValueError(f"no user, group or machine {entity_id}")
        rings = [dict(r) for r in s.run(
            f"""
            MATCH p = (start {{id: $id}})-[:{ATTACK_EDGES}*1..3]->(n)
            WHERE NOT n.id IN [x IN nodes(p)[..-1] | x.id]
            WITH n, min(length(p)) AS hop
            RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, coalesce(n.critical, false) AS critical, hop
            """, id=entity_id)]
        path = s.run(
            f"""
            MATCH (start {{id: $id}}), (c) WHERE c.critical = true AND c <> start
            MATCH p = shortestPath((start)-[:{ATTACK_EDGES}*..6]->(c))
            RETURN [x IN nodes(p) | x.id] AS ids, [r IN relationships(p) | type(r)] AS types
            ORDER BY length(p) LIMIT 1
            """, id=entity_id).single()
    return {"nodes": [{**dict(start), "hop": 0}] + [r for r in rings if r["id"] != entity_id],
            "attack_path": {"nodes": path["ids"], "types": path["types"]} if path else None}


@app.get("/api/learning")
def learning():
    """the ranking model learned from analyst verdicts so far, next to the hand-set weights. not applied."""
    from . import learn
    with _driver.session() as s:
        return learn.from_verdicts(s)


@app.get("/api/explore/{entity_id}")
def explore_entity(entity_id: str, max_hops: int = 8):
    """everything one user, group or machine can reach, and its attack paths to critical assets."""
    from . import explore
    if not 1 <= max_hops <= 8:
        raise HTTPException(422, "max_hops must be between 1 and 8")
    with _driver.session() as s:
        result = explore.explore(s, entity_id, max_hops)
    if result is None:
        raise HTTPException(404, "no such user, group or machine")
    return result


@app.get("/api/entities")
def entities():
    """every user, group and machine, for pickers."""
    with _driver.session() as s:
        return [dict(r) for r in s.run(
            """
            MATCH (n) WHERE n:Entity
            RETURN n.id AS id, [l IN labels(n) WHERE l <> 'Entity'][0] AS kind, coalesce(n.critical, false) AS critical, n.zone AS zone,
                   n.location AS location, n.name AS name
            ORDER BY kind, id
            """)]


class Control(BaseModel):
    src: str
    type: str
    dst: str
    secured: bool = True
    note: str | None = None


@app.post("/api/controls")
def set_control(body: Control):
    """record that one attack step is secured (or no longer secured), with a short note such as "mfa enforced"."""
    from . import explore
    try:
        with _driver.session() as s:
            n = explore.set_secured(s, body.src, body.type, body.dst, body.secured, body.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if not n:
        raise HTTPException(404, "no such step")
    return {"updated": n}


@app.get("/api/vulnerabilities")
def vulnerabilities():
    """serious cves on the software each machine runs, from nvd, cisa kev and first epss."""
    from . import vulns
    with _driver.session() as s:
        return vulns.summary(s)


@app.post("/api/vulnerabilities/refresh")
def refresh_vulnerabilities():
    """fetch nvd, cisa kev and epss again, update the graph and re-score."""
    from . import vulns
    with _driver.session() as s:
        result = vulns.refresh(s, live=True)
        _reanalyse(s)
    return result


@app.get("/api/languages")
def languages():
    """languages the story and the ask tab can answer in, and whether the llm is configured."""
    from . import llm
    return {"languages": [{"code": k, "name": v} for k, v in LANGUAGES.items()], "llm": llm.available()}


@app.get("/api/health")
def health():
    """liveness and readiness for load balancers and ops probes: 200 with live Neo4j connectivity status."""
    neo4j_ok = True
    try:
        _driver.verify_connectivity()
    except Exception:
        neo4j_ok = False
    return {"status": "ok" if neo4j_ok else "degraded", "neo4j": neo4j_ok,
            "time": dt.datetime.now(dt.timezone.utc).isoformat()}


# serve the built dashboard from the same server when it exists (used on vercel and in production)
_DIST = ROOT / "frontend" / "dist"
if _DIST.is_dir():
    app.frontend("/", directory=str(_DIST))
