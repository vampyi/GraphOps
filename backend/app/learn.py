"""ranking model that learns from analyst verdicts (the first of the pitch's three ai parts).

every alert already carries seven ranking features (f_hops, f_blast, ...), each between 0 and 1. an analyst's
verdict labels it: 'real' is an attack (1), 'false' and 'benign' are not (0). a small logistic regression learns
how much each feature should count. it is written in plain python because the hosted site cannot install numpy
or scikit-learn, and the data is tiny.

the learned weights are shown next to the hand-set ones; they are not switched on automatically."""
import math

from .scoring import WEIGHTS

FEATURES = list(WEIGHTS)  # hops, blast, linked, never_taken, stages, choke, severity
MIN_VERDICTS = 8
MIN_PER_CLASS = 3


def fit(rows, labels, l2=0.1, rate=0.5, epochs=2000):
    """logistic regression by gradient descent. rows are lists of feature values, labels are 0 or 1.
    returns (bias, coefficients)."""
    n, k = len(rows), len(rows[0])
    bias, coef = 0.0, [0.0] * k
    for _ in range(epochs):
        g_bias, g_coef = 0.0, [0.0] * k
        for x, y in zip(rows, labels):
            z = bias + sum(c * v for c, v in zip(coef, x))
            p = 1 / (1 + math.exp(-max(-30, min(30, z))))
            err = p - y
            g_bias += err
            for j in range(k):
                g_coef[j] += err * x[j]
        bias -= rate * g_bias / n
        coef = [c - rate * (g / n + l2 * c) for c, g in zip(coef, g_coef)]
    return bias, coef


def as_weights(coef):
    """turn coefficients into weights that sum to 100 like the hand-set ones. a negative coefficient means the
    feature pointed away from real attacks in the verdicts; it gets weight 0 and is reported."""
    pos = [max(0.0, c) for c in coef]
    total = sum(pos) or 1.0
    return {f: round(100 * p / total, 1) for f, p in zip(FEATURES, pos)}


def score(features, weights):
    return sum(weights[f] * (features.get(f) or 0) for f in FEATURES)


def labelled_rows(session):
    rows = session.run(
        """
        MATCH (a:Alert) WHERE a.status IN ['real', 'false', 'benign']
        RETURN a.id AS id, a.status AS status,
               {hops: a.f_hops, blast: a.f_blast, linked: a.f_linked, never_taken: a.f_never_taken,
                stages: a.f_stages, choke: a.f_choke, severity: a.f_severity} AS f
        """)
    return [dict(r) for r in rows]


def from_verdicts(session):
    """learn from the analyst verdicts saved so far, or say what is still missing."""
    rows = labelled_rows(session)
    real = sum(r["status"] == "real" for r in rows)
    other = len(rows) - real
    status = {"verdicts": len(rows), "real": real, "not_real": other, "min_verdicts": MIN_VERDICTS,
              "min_per_class": MIN_PER_CLASS, "hand_weights": dict(WEIGHTS), "applied": False}
    if len(rows) < MIN_VERDICTS or real < MIN_PER_CLASS or other < MIN_PER_CLASS:
        return {**status, "ready": False}
    bias, coef = fit([[r["f"].get(f) or 0 for f in FEATURES] for r in rows], [int(r["status"] == "real") for r in rows])
    return {**status, "ready": True, "learned_weights": as_weights(coef),
            "coefficients": {f: round(c, 3) for f, c in zip(FEATURES, coef)},
            "pointed_away": [f for f, c in zip(FEATURES, coef) if c < 0]}
