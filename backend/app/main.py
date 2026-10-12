"""backend server: the api the dashboard calls."""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .db import ROOT, driver
from .scoring import WEIGHTS
from .story import write_story

app = FastAPI(title="GraphOps")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])
_driver = driver()

ATTACK_EDGES = "MemberOf|AdminTo|CanRDP|GenericAll|HasSession|RemoteLogon"


@app.get("/api/alerts")
def alerts():
    with _driver.session() as s:
        return _with_breakdown([dict(r) for r in s.run(
            """
            MATCH (a:Alert)
            OPTIONAL MATCH (a)-[:Involves]->(e)
            WITH a, collect(e.id) AS involves
            RETURN a.id AS id, a.time AS time, a.name AS name, a.severity AS severity,
                   a.score AS score, a.reasons AS reasons, a.incident_id AS incident_id,
                   a.tactic_id AS tactic_id, a.technique_id AS technique_id, a.status AS status,
                   a.source_tool AS source_tool, involves,
                   {hops: a.f_hops, blast: a.f_blast, linked: a.f_linked, never_taken: a.f_never_taken,
                    stages: a.f_stages, choke: a.f_choke, severity: a.f_severity} AS features
            ORDER BY a.score DESC, a.time
            """)])


def _with_breakdown(rows):
    """points each ranking question added to the score, so the dashboard can draw them as bars."""
    for r in rows:
        f = r.pop("features") or {}
        r["breakdown"] = {k: round(WEIGHTS[k] * (f.get(k) or 0), 1) for k in WEIGHTS}
    return rows


@app.get("/api/alerts/{alert_id}/blast-radius")
def blast_radius(alert_id: str):
    """everything reachable from the alert's machines and users in 1, 2 and 3 attack steps."""
    with _driver.session() as s:
        if not s.run("MATCH (a:Alert {id: $id}) RETURN a", id=alert_id).single():
            raise HTTPException(404, "alert not found")
        rings = [dict(r) for r in s.run(
            f"""
            MATCH (a:Alert {{id: $id}})-[:Involves]->(start)
            MATCH p = (start)-[:{ATTACK_EDGES}*1..3]->(n)
            WHERE NOT n.id IN [x IN nodes(p)[..-1] | x.id]
            WITH n, min(length(p)) AS hop
            RETURN n.id AS id, labels(n)[0] AS kind, coalesce(n.critical, false) AS critical, hop
            ORDER BY hop, id
            """, id=alert_id)]
        starts = [dict(r) for r in s.run(
            "MATCH (:Alert {id: $id})-[:Involves]->(e) RETURN e.id AS id, labels(e)[0] AS kind, coalesce(e.critical, false) AS critical, 0 AS hop",
            id=alert_id)]
        start_ids = {x["id"] for x in starts}
        nodes = starts + [r for r in rings if r["id"] not in start_ids]
        ids = [n["id"] for n in nodes]
        edges = [dict(r) for r in s.run(
            f"""
            MATCH (x)-[r:{ATTACK_EDGES}]->(y) WHERE x.id IN $ids AND y.id IN $ids
            RETURN x.id AS src, type(r) AS type, y.id AS dst
            """, ids=ids)]
        details = {r["id"]: r for r in (dict(x) for x in s.run(
            """
            MATCH (n) WHERE n.id IN $ids
            RETURN n.id AS id, n.name AS name, n.zone AS zone, n.os AS os, n.owner AS owner,
                   n.hops_to_critical AS hops_to_critical, n.critical_within_3 AS critical_within_3,
                   round(coalesce(n.choke_score, 0), 2) AS choke_score
            """, ids=ids))}
        for n in nodes:
            n.update({k: v for k, v in details.get(n["id"], {}).items() if k != "id"})
        path = s.run(
            f"""
            MATCH (:Alert {{id: $id}})-[:Involves]->(start)
            MATCH (c) WHERE c.critical = true AND c <> start
            MATCH p = shortestPath((start)-[:{ATTACK_EDGES}*..6]->(c))
            RETURN [x IN nodes(p) | x.id] AS ids, [r IN relationships(p) | type(r)] AS types
            ORDER BY length(p) LIMIT 1
            """, id=alert_id).single()
        attack_path = {"nodes": path["ids"], "types": path["types"]} if path else None
        return {"alert_id": alert_id, "nodes": nodes, "edges": edges, "attack_path": attack_path}


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):
    with _driver.session() as s:
        rows = [dict(r) for r in s.run(
            """
            MATCH (a:Alert {incident_id: $id})
            RETURN a.id AS id, a.time AS time, a.name AS name, a.tactic_id AS tactic_id,
                   a.technique_id AS technique_id, a.score AS score, a.status AS status
            ORDER BY a.time
            """, id=incident_id)]
        if not rows:
            raise HTTPException(404, "incident not found")
        return {"id": incident_id, "alerts": rows}


@app.post("/api/incidents/{incident_id}/story")
def story(incident_id: str):
    with _driver.session() as s:
        result = write_story(s, incident_id)
        if result is None:
            raise HTTPException(404, "incident not found")
        return result


class Verdict(BaseModel):
    status: str


@app.post("/api/alerts/{alert_id}/verdict")
def verdict(alert_id: str, body: Verdict):
    if body.status not in ("real", "false"):
        raise HTTPException(422, "status must be 'real' or 'false'")
    with _driver.session() as s:
        r = s.run("MATCH (a:Alert {id: $id}) SET a.status = $st RETURN a.status AS status",
                  id=alert_id, st=body.status).single()
        if not r:
            raise HTTPException(404, "alert not found")
        return {"id": alert_id, "status": r["status"]}


# serve the built dashboard from the same server when it exists (used on vercel and in production)
_DIST = ROOT / "frontend" / "dist"
if _DIST.is_dir():
    app.frontend("/", directory=str(_DIST))
