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


def catalog():
    items = [{"id": "sample", "name": "Sample day", "path": str(SAMPLE_ALERTS),
              "description": "The default demo day: a lateral-movement attack to the customer database."}]
    for f in sorted(SCENARIO_DIR.glob("*.json")):
        doc = json.loads(f.read_text())
        items.append({"id": f.stem, "name": f.stem.replace("_", " ").title(), "path": str(f),
                      "description": doc.get("description", "")})
    return items


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
