"""run the honest evaluation on every labelled day: the sample day and each held-out scenario.

    python -m app.evaluate_all

for each day it loads the alerts, ranks them with the frozen hand-set weights and compares GraphOps' order with
sorting by the tools' own severity. it also checks grouping: how many incidents the attack is split across and
how many noise alerts are pulled into them. labels are read from the scenario files, never by the ranker.

warning: loading a scenario replaces everything in the database it points at. run it against a local or test
database, never the hosted one."""
import json
import sys

from . import learn, scenarios
from .evaluate import _order_metrics, evaluate


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


def day_rows(session, attack_ids):
    rows = session.run(
        """
        MATCH (a:Alert)
        RETURN a.id AS id, a.time AS time, a.score AS score,
               {hops: a.f_hops, blast: a.f_blast, linked: a.f_linked, never_taken: a.f_never_taken,
                stages: a.f_stages, choke: a.f_choke, severity: a.f_severity} AS f
        """)
    attack = set(attack_ids)
    return [{**dict(r), "attack": r["id"] in attack} for r in rows]


def learning_experiment(session):
    """leave one day out: learn weights from the labels of every other day, rank the held-out day with them,
    and compare with the hand-set weights. labels stand in for analyst verdicts; they are never seen by the
    hand-set ranker."""
    days = {}
    for item in scenarios.catalog():
        loaded = scenarios.load_scenario(session, item["id"])
        days[item["id"]] = (day_rows(session, loaded["attack_ids"]), set(loaded["attack_ids"]))
    out = []
    for held, (rows, attack) in days.items():
        train = [r for d, (rs, _) in days.items() if d != held for r in rs]
        _, coef = learn.fit([[r["f"].get(f) or 0 for f in learn.FEATURES] for r in train], [int(r["attack"]) for r in train])
        weights = learn.as_weights(coef)
        by_learned = [r["id"] for r in sorted(rows, key=lambda r: (-learn.score(r["f"], weights), r["time"]))]
        by_hand = [r["id"] for r in sorted(rows, key=lambda r: (-r["score"], r["time"]))]
        out.append({"held_out": held, "hand": _order_metrics(by_hand, attack), "learned": _order_metrics(by_learned, attack),
                    "learned_weights": weights})
    return out


def learning_table(results):
    lines = ["| Held-out day | Last attack rank: hand-set / learned | False alarms before first attack: hand-set / learned | Average precision: hand-set / learned |",
             "|---|---|---|---|"]
    for r in results:
        h, l = r["hand"], r["learned"]
        lines.append(f"| {r['held_out']} | {h['last_attack_rank']} / {l['last_attack_rank']} | {h['false_before_first']} / {l['false_before_first']} | "
                     f"{h['average_precision']} / {l['average_precision']} |")
    return "\n".join(lines)


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
        if "--learn" in sys.argv:
            res = learning_experiment(s)
            print(json.dumps(res, indent=2) if "--json" in sys.argv else learning_table(res))
        else:
            out = run(s)
            print(json.dumps(out, indent=2) if "--json" in sys.argv else table(out))
