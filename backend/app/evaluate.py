"""measure the ranking honestly: does GraphOps put the attack above the noise, and better than sorting by the
tools' own severity? we report precision@5, recall@5, the rank of the first and last attack alert, how many
false alarms you read before the first real one, and average precision. attack labels come from the loaded
scenario and are never seen by the ranker.

these are the measures the research notes recommend (precision@k and alerts-to-first-attack, not AUC alone)."""
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
K = 5


def _rows(session):
    return [dict(r) for r in session.run(
        "MATCH (a:Alert) RETURN a.id AS id, coalesce(a.score, 0) AS score, a.severity AS severity, a.time AS time")]


def _order_metrics(ordered, attack):
    n = len(ordered)
    k = min(K, n)
    ranks = [i + 1 for i, aid in enumerate(ordered) if aid in attack]
    tp_at_k = sum(1 for aid in ordered[:k] if aid in attack)
    hits = ap = 0
    for i, aid in enumerate(ordered, 1):
        if aid in attack:
            hits += 1
            ap += hits / i
    return {
        "precision_at_5": round(tp_at_k / k, 3) if k else 0.0,
        "recall_at_5": round(tp_at_k / len(attack), 3) if attack else 0.0,
        "first_attack_rank": min(ranks) if ranks else None,
        "last_attack_rank": max(ranks) if ranks else None,
        "false_before_first": (min(ranks) - 1) if ranks else n,
        "average_precision": round(ap / len(attack), 3) if attack else 0.0,
    }


def evaluate(session, attack_ids):
    """GraphOps order (by score) vs severity-only order (the order most tools use), against the attack labels."""
    rows = _rows(session)
    attack = set(attack_ids)
    # rows carry a stable time; sort both orders deterministically with time as the tiebreak
    graphops = [r["id"] for r in sorted(rows, key=lambda r: (-r["score"], r["time"]))]
    severity = [r["id"] for r in sorted(rows, key=lambda r: (-SEV_RANK.get(r["severity"], 0), r["time"]))]
    go, sv = _order_metrics(graphops, attack), _order_metrics(severity, attack)
    return {
        "total": len(rows), "attack": len(attack & {r["id"] for r in rows}),
        "graphops": go, "severity": sv,
        "headline": {
            "graphops_last_rank": go["last_attack_rank"],
            "severity_last_rank": sv["last_attack_rank"],
            "graphops_false_before_first": go["false_before_first"],
            "severity_false_before_first": sv["false_before_first"],
        },
    }
