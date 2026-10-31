"""labelled days GraphOps can load. the sample day is the one the demo and the hand-set weights are tuned on;
the held-out scenarios in data/scenarios/ are different attacks on the same network, used to show the ranking
is not overfit to one script. the 'scenario' label on each alert is used only to evaluate, never by the ranker."""
import json
from pathlib import Path

from .analysis import run_all
from .db import ROOT
from .scoring import score_all
from .seed import SAMPLE, load

SCENARIO_DIR = ROOT / "data" / "scenarios"
BASE_NETWORK = SAMPLE / "network.json"
SAMPLE_ALERTS = SAMPLE / "alerts.json"


def _attack_ids(alerts_path):
    doc = json.loads(Path(alerts_path).read_text())
    return sorted(a["id"] for a in doc["alerts"] if a.get("scenario") == "attack")


# the days a visitor can pick, in order: the real lab recording first, then the synthetic company. the other days
# stay in data/scenarios/ as test days for the proof table (app.evaluate_all), not in the picker
LISTED = {"apt29_day1_sigma": ("APT29 lab day (real logs)", True), "sample": ("Demo company (synthetic)", False)}


def catalog():
    items = [{"id": "sample", "name": "Lateral movement to customer database", "path": str(SAMPLE_ALERTS),
              "description": "The tuning day: a lateral-movement attack to the customer database."}]
    for f in sorted(SCENARIO_DIR.glob("*.json")):
        doc = json.loads(f.read_text())
        items.append({"id": f.stem, "name": doc.get("name") or f.stem.replace("_", " ").capitalize(), "path": str(f),
                      "description": doc.get("description", "")})
    for it in items:
        it["listed"] = it["id"] in LISTED
        it["real"] = it["id"].startswith("apt29")
    return items


def picker():
    """the days shown in the scenario picker, with their short names."""
    by_id = {c["id"]: c for c in catalog()}
    return [{**by_id[i], "name": name, "real": real} for i, (name, real) in LISTED.items() if i in by_id]


def _path_for(scenario_id):
    return {c["id"]: c["path"] for c in catalog()}.get(scenario_id)


def active(session):
    """the currently loaded scenario and its attack labels. defaults to the sample day when nothing is marked."""
    r = session.run("MATCH (m:Meta {id: 'active_scenario'}) RETURN m.scenario AS s, m.attack_ids AS ids").single()
    if r and r["ids"] is not None:
        return {"id": r["s"], "attack_ids": list(r["ids"])}
    return {"id": "sample", "attack_ids": _attack_ids(SAMPLE_ALERTS)}


def mark_active(session, scenario_id, attack_ids):
    session.run("MERGE (m:Meta {id: 'active_scenario'}) SET m.scenario = $s, m.attack_ids = $ids",
                s=scenario_id, ids=attack_ids)


def load_scenario(session, scenario_id):
    """replace the graph with the chosen day (same base network, that day's alerts), score it, and record which
    alerts are the attack so the evaluation can measure the ranking."""
    path = _path_for(scenario_id)
    if path is None:
        return None
    counts = load(session, network_path=BASE_NETWORK, alerts_path=Path(path))
    run_all(session)
    score_all(session)
    ids = _attack_ids(path)
    mark_active(session, scenario_id, ids)
    return {"id": scenario_id, "attack_ids": ids, "counts": counts}


# the hosted demo has one shared database, so only one visitor at a time may reload it (a scenario load or a live
# stream). the lock lives in neo4j, not in memory, because each vercel function instance has its own memory. a
# lock older than LOCK_SECONDS is treated as abandoned, so a crashed load never blocks the demo for good.
LOCK_SECONDS = 300


def acquire(session, what):
    row = session.run(
        """
        MERGE (l:Lock {id: 'demo'})
        WITH l, l.until IS NULL OR l.until < datetime() AS free
        FOREACH (_ IN CASE WHEN free THEN [1] ELSE [] END |
          SET l.until = datetime() + duration({seconds: $ttl}), l.what = $what)
        RETURN free
        """, ttl=LOCK_SECONDS, what=what).single()
    return bool(row and row["free"])


def release(session):
    session.run("MATCH (l:Lock {id: 'demo'}) SET l.until = null, l.what = null")


def busy(session):
    row = session.run("MATCH (l:Lock {id: 'demo'}) WHERE l.until >= datetime() RETURN l.what AS what").single()
    return row["what"] if row else None
