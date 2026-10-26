"""run the honest evaluation on every labelled day: the sample day and each held-out scenario.

    python -m app.evaluate_all

for each day it loads the alerts, ranks them with the frozen hand-set weights and compares GraphOps' order with
sorting by the tools' own severity. it also checks grouping: how many incidents the attack is split across and
how many noise alerts are pulled into them. labels are read from the scenario files, never by the ranker.

warning: loading a scenario replaces everything in the database it points at. run it against a local or test
database, never the hosted one."""
import json
import sys

from . import scenarios
from .evaluate import evaluate


def grouping(session, attack_ids):
    rows = [dict(r) for r in session.run("MATCH (a:Alert) RETURN a.id AS id, a.incident_id AS inc")]
    attack = set(attack_ids)
    incidents = {r["inc"] for r in rows if r["id"] in attack}
    pulled_in = [r["id"] for r in rows if r["inc"] in incidents and r["id"] not in attack]
    return {"attack_incidents": len(incidents), "noise_in_attack_incidents": len(pulled_in)}


def run(session):
    results = []
    for item in scenarios.catalog():
        loaded = scenarios.load_scenario(session, item["id"])
        ev = evaluate(session, loaded["attack_ids"])
        results.append({"scenario": item["id"], "alerts": ev["total"], "attack": ev["attack"],
                        "graphops": ev["graphops"], "severity": ev["severity"],
                        **grouping(session, loaded["attack_ids"])})
    return results


def table(results):
    head = ("| Day | Alerts | Attack | Last attack rank: GraphOps / severity | False alarms before first attack: "
            "GraphOps / severity | Precision@5: GraphOps / severity | Incidents the attack is split across | "
            "Noise alerts pulled into the attack |\n|---|---|---|---|---|---|---|---|")
    lines = [head]
    for r in results:
        g, s = r["graphops"], r["severity"]
        lines.append(f"| {r['scenario']} | {r['alerts']} | {r['attack']} | {g['last_attack_rank']} / {s['last_attack_rank']} | "
                     f"{g['false_before_first']} / {s['false_before_first']} | {g['precision_at_5']} / {s['precision_at_5']} | "
                     f"{r['attack_incidents']} | {r['noise_in_attack_incidents']} |")
    return "\n".join(lines)


if __name__ == "__main__":
    from .db import driver
    with driver() as d, d.session() as s:
        out = run(s)
    print(json.dumps(out, indent=2) if "--json" in sys.argv else table(out))
