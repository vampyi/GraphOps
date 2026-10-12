"""alert ranker: score every alert with graph questions and link related alerts into incidents."""
from datetime import datetime, timedelta

WINDOW = timedelta(hours=2)        # alerts sharing a user or machine
PATH_WINDOW = timedelta(minutes=45)  # alerts joined by a login from one machine to the next
TACTIC_ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0112",
                "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040"]
SEVERITY = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}

# hand-set weights (our design choice, documented in docs/schema.md). they sum to 100.
WEIGHTS = {"hops": 25, "blast": 15, "linked": 20, "never_taken": 15, "stages": 15, "choke": 5, "severity": 5}


def _t(s):
    return datetime.fromisoformat(s)


def fetch_alerts(session):
    rows = session.run(
        """
        MATCH (a:Alert)-[:Involves]->(e)
        WITH a, collect(e {.id, .hops_to_critical, .critical_within_3, .choke_score, labels: labels(e)}) AS ents
        RETURN a {.*} AS alert, ents
        ORDER BY a.time
        """
    )
    return [dict(r["alert"], entities=r["ents"]) for r in rows]


def observed_links(session):
    """observed edges with their time span, used to link alerts along paths the attacker actually took."""
    return [dict(r) for r in session.run(
        """
        MATCH (s)-[r:RemoteLogon|LoggedInto|ConnectedTo]->(d)
        RETURN type(r) AS type, s.id AS src, d.id AS dst, r.user AS user,
               r.first_seen AS first_seen, r.last_seen AS last_seen
        """
    )]


def new_edges_near(alert, links):
    """login routes touching the alert's entities that were used for the first time shortly before the alert."""
    ids = {e["id"] for e in alert["entities"]}
    t = _t(alert["time"])
    out = []
    for l in links:
        if l["type"] != "RemoteLogon" or not l["first_seen"]:
            continue
        if not (l["src"] in ids or l["dst"] in ids or l.get("user") in ids):
            continue
        first = _t(l["first_seen"])
        if first <= t and t - first <= WINDOW:
            out.append(l)
    return out


def link_alerts(alerts, links):
    """link two alerts when they share a user or machine within WINDOW, or when a login went from the
    earlier alert's machine to the later alert's machine between the two alerts, within PATH_WINDOW."""
    parent = {a["id"]: a["id"] for a in alerts}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    hops = [l for l in links if l["type"] == "RemoteLogon" and l["last_seen"]]
    ordered = sorted(alerts, key=lambda a: a["time"])
    for i, a in enumerate(ordered):
        ids_a, t_a = {e["id"] for e in a["entities"]}, _t(a["time"])
        for b in ordered[i + 1:]:
            ids_b, t_b = {e["id"] for e in b["entities"]}, _t(b["time"])
            if t_b - t_a <= WINDOW and ids_a & ids_b:
                union(a["id"], b["id"])
                continue
            if t_b - t_a <= PATH_WINDOW:
                for l in hops:
                    if l["src"] in ids_a and l["dst"] in ids_b and t_a <= _t(l["last_seen"]) <= t_b:
                        union(a["id"], b["id"])
                        break
    groups = {}
    for a in alerts:
        groups.setdefault(find(a["id"]), []).append(a)
    return list(groups.values())


def stages_in_order(group):
    """number of distinct attack stages in the incident that appear in kill-chain order over time."""
    seen = []
    for a in sorted(group, key=lambda x: x["time"]):
        tac = a.get("tactic_id")
        if tac in TACTIC_ORDER:
            idx = TACTIC_ORDER.index(tac)
            if not seen or idx >= seen[-1]:
                if not seen or idx != seen[-1]:
                    seen.append(idx)
    return len(seen)


def score_alert(alert, group, new_edges):
    ents = alert["entities"]
    hops = [e["hops_to_critical"] for e in ents if e.get("hops_to_critical") is not None]
    best_hops = min(hops) if hops else None
    blast = max((e.get("critical_within_3") or 0) for e in ents) if ents else 0
    choke = max((e.get("choke_score") or 0) for e in ents) if ents else 0
    linked = len(group) - 1
    never = len(new_edges) > 0
    stages = stages_in_order(group)

    f = {
        "hops": 0 if best_hops is None else max(0, 4 - best_hops) / 4,
        "blast": min(blast, 3) / 3,
        "linked": min(linked, 3) / 3,
        "never_taken": 1.0 if never else 0.0,
        "stages": 0 if stages < 2 else min(stages - 1, 3) / 3,
        "choke": choke,
        "severity": SEVERITY.get(alert.get("severity"), 0),
    }
    score = round(sum(WEIGHTS[k] * f[k] for k in WEIGHTS), 1)

    reasons = []
    if best_hops is not None and best_hops <= 3:
        reasons.append(f"{best_hops} step{'s' if best_hops != 1 else ''} from a critical asset")
    if blast:
        reasons.append(f"{blast} critical asset{'s' if blast != 1 else ''} within 3 hops")
    if linked:
        reasons.append(f"linked to {linked} other alert{'s' if linked != 1 else ''}")
    if never:
        reasons.append("involves a path never used before")
    if stages >= 2:
        reasons.append(f"incident follows {stages} attack stages in order")
    if choke >= 0.5:
        reasons.append("sits on a choke point")
    return score, reasons, f


def score_all(session):
    alerts = fetch_alerts(session)
    links = observed_links(session)
    groups = link_alerts(alerts, links)
    session.run("MATCH (i:Incident) DETACH DELETE i")
    for n, group in enumerate(sorted(groups, key=lambda g: min(a["time"] for a in g)), 1):
        incident_id = f"inc-{n:02d}"
        session.run("CREATE (:Incident {id: $id, size: $size})", id=incident_id, size=len(group))
        for a in group:
            score, reasons, features = score_alert(a, group, new_edges_near(a, links))
            session.run(
                """
                MATCH (a:Alert {id: $id}), (i:Incident {id: $inc})
                SET a.score = $score, a.reasons = $reasons, a.incident_id = $inc,
                    a.f_hops = $f.hops, a.f_blast = $f.blast, a.f_linked = $f.linked,
                    a.f_never_taken = $f.never_taken, a.f_stages = $f.stages,
                    a.f_choke = $f.choke, a.f_severity = $f.severity
                MERGE (a)-[:PartOf]->(i)
                """,
                id=a["id"], inc=incident_id, score=score, reasons=reasons, f=features,
            )
    session.run(
        """
        MATCH (i:Incident)<-[:PartOf]-(a:Alert)
        WITH i, max(a.score) AS top
        SET i.score = top
        """
    )
