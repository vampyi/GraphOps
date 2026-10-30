"""incident report: a containment-ready write-up of one incident, in markdown.

its sections follow what an on-call analyst needs and what CERT-In's 6-hour report asks for: what happened, in
attack-stage order; which assets are affected; what the compromise can still reach; and what to do about it.
every fact comes from the graph, so the report is evidence, not prose."""
from .attack import ATTACK_EDGES, TECHNIQUES, describe_removal, tag
from .scoring import TACTIC_ORDER

TACTIC_NAMES = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0112": "Defense Impairment", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0011": "Command and Control", "TA0010": "Exfiltration", "TA0040": "Impact",
}
REL = "|".join(ATTACK_EDGES)


def _stage_rank(tactic):
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)


def gather(session, incident_id):
    meta = session.run(
        """
        MATCH (i:Incident {id: $id})
        RETURN i.status AS status, i.notes AS notes, i.opened_at AS opened_at, i.score AS score,
               i.communities AS communities, i.lateral AS lateral, i.stages AS stages
        """, id=incident_id).single()
    alerts = [dict(r) for r in session.run(
        """
        MATCH (a:Alert {incident_id: $id})
        OPTIONAL MATCH (a)-[:Involves]->(e)
        WITH a, collect(e.id) AS involves
        RETURN a.id AS id, a.time AS time, a.name AS name, a.severity AS severity, a.score AS score,
               a.tactic_id AS tactic_id, a.technique_id AS technique_id, a.source_tool AS source_tool,
               a.status AS status, involves
        ORDER BY a.time
        """, id=incident_id)]
    if not alerts:
        return None
    entity_ids = sorted({e for a in alerts for e in a["involves"]})
    entities = [dict(r) for r in session.run(
        """
        MATCH (e) WHERE e.id IN $ids
        RETURN e.id AS id, [l IN labels(e) WHERE l <> 'Entity'][0] AS kind, coalesce(e.critical, false) AS critical, e.zone AS zone,
               e.hops_to_critical AS hops_to_critical, e.critical_within_3 AS critical_within_3,
               e.community AS community
        ORDER BY critical DESC, id
        """, ids=entity_ids)]
    path = session.run(
        f"""
        MATCH (a:Alert {{incident_id: $id}})-[:Involves]->(start)
        MATCH (c) WHERE c.critical = true AND c <> start
        MATCH p = shortestPath((start)-[:{REL}*..6]->(c))
        RETURN [x IN nodes(p) | x.id] AS ids, [r IN relationships(p) | type(r)] AS types
        ORDER BY length(p) LIMIT 1
        """, id=incident_id).single()
    attack_path = {"nodes": path["ids"], "types": path["types"]} if path else None
    return {"meta": dict(meta) if meta else {}, "alerts": alerts, "entities": entities, "attack_path": attack_path}


def entry_point(alerts):
    """how the attack got in: the earliest alert tagged Initial Access (TA0001). when none of the incident's alerts
    is, the way in was not seen, which is itself worth saying: the first alert is already a later stage."""
    alerts = sorted(alerts, key=lambda a: a["time"])
    first = next((a for a in alerts if a.get("tactic_id") == "TA0001"), None)
    if first:
        tech = first.get("technique_id")
        return {"seen": True, "alert": first["id"], "name": first["name"], "time": first["time"],
                "on": first.get("involves", []), "technique": tech, "how": TECHNIQUES.get(tech, first["name"])}
    a = alerts[0]
    return {"seen": False, "alert": a["id"], "name": a["name"], "time": a["time"], "on": a.get("involves", []),
            "stage": TACTIC_NAMES.get(a.get("tactic_id"), "an unknown stage")}


def entry_line(e):
    on = ", ".join(e["on"])
    if e["seen"]:
        return f"{e['how']} ({e['technique']}) on {on} at {e['time'][11:16]}: {e['name']}"
    return (f"Entry point not seen. The first alert is already {e['stage']}: {e['name']} on {on} at "
            f"{e['time'][11:16]}. Look further back on {on} for how the attacker got in.")


def incident_report(session, incident_id):
    data = gather(session, incident_id)
    if data is None:
        return None
    meta, alerts, entities, path = data["meta"], data["alerts"], data["entities"], data["attack_path"]
    ordered = sorted(alerts, key=lambda a: (_stage_rank(a.get("tactic_id")), a["time"]))
    crit = [e for e in entities if e["critical"]]
    reachable = max((e.get("critical_within_3") or 0) for e in entities) if entities else 0
    times = [a["time"] for a in alerts]

    lines = [f"# Incident {incident_id}", ""]
    lines.append(f"- **Status:** {meta.get('status', 'open')}")
    lines.append(f"- **Opened:** {meta.get('opened_at', times[0])[:16].replace('T', ' ')}")
    lines.append(f"- **Alerts:** {len(alerts)} between {times[0][11:16]} and {times[-1][11:16]}")
    lines.append(f"- **How it started:** {entry_line(entry_point(alerts))}")
    lines.append(f"- **Highest score:** {round(meta.get('score') or max(a['score'] or 0 for a in alerts))}")
    if meta.get("lateral"):
        lines.append(f"- **Lateral movement:** yes, the alerts span {len(meta.get('communities') or [])} activity communities")
    lines += ["", "## What happened", ""]
    lines.append("The alerts below are ordered by MITRE ATT&CK stage, so they read as one attack rather than "
                 "separate events.")
    lines.append("")
    lines.append("| Stage | Time | Alert | Technique | On | Tool |")
    lines.append("|---|---|---|---|---|---|")
    for a in ordered:
        stage = TACTIC_NAMES.get(a.get("tactic_id"), "(no stage)")
        tech = a.get("technique_id") or "(none)"
        lines.append(f"| {stage} | {a['time'][11:16]} | {a['name']} | {tech} | {', '.join(a['involves'])} | {a['source_tool']} |")

    lines += ["", "## Affected assets", ""]
    for e in entities:
        bits = [e["kind"]]
        if e["critical"]:
            bits.append("critical asset")
        if e.get("zone"):
            bits.append(f"{e['zone'].replace('_', ' ')} zone")
        if e.get("hops_to_critical") is not None:
            bits.append(f"{e['hops_to_critical']} hop(s) from a critical asset")
        lines.append(f"- **{e['id']}** - {', '.join(bits)}")

    lines += ["", "## What the compromise can reach", ""]
    if crit:
        lines.append(f"The incident already involves {len(crit)} critical asset(s): {', '.join(e['id'] for e in crit)}.")
    else:
        lines.append(f"No critical asset is directly involved. The closest involved entity sits "
                     f"{min((e.get('hops_to_critical') for e in entities if e.get('hops_to_critical') is not None), default='an unknown number of')} "
                     f"hop(s) from one, and {reachable} critical asset(s) sit within 3 hops.")
    if path:
        steps = " → ".join([f"**{path['nodes'][0]}**"] +
                           [f"{tag(t)['step']} **{path['nodes'][i + 1]}**" for i, t in enumerate(path["types"])])
        lines += ["", f"Shortest attack path to a critical asset: {steps}."]

    lines += ["", "## Recommended containment", ""]
    recs = []
    if path:
        for a, t, b in zip(path["nodes"], path["types"], path["nodes"][1:]):
            recs.append(describe_removal(a, t, b))
    verdict_real = [a for a in alerts if a.get("status") == "real"]
    if verdict_real:
        recs.insert(0, f"Treat as a live incident: {len(verdict_real)} alert(s) confirmed real by an analyst.")
    recs.append("Reset credentials for every account named above and review its group memberships.")
    for r in dict.fromkeys(recs):
        lines.append(f"- {r}")

    if meta.get("notes"):
        lines += ["", "## Analyst notes", "", meta["notes"]]

    lines += ["", "---", "*Generated by GraphOps from the incident graph. Synthetic data.*"]
    return {"id": incident_id, "markdown": "\n".join(lines),
            "summary": {"alerts": len(alerts), "critical_involved": len(crit), "reachable_within_3": reachable,
                        "lateral": bool(meta.get("lateral")), "has_path": path is not None}}
