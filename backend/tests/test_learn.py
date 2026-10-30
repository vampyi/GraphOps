"""the ranking model that learns from verdicts: the maths on known data, and the readiness rules."""
from app import learn


def test_fit_learns_the_feature_that_separates_the_classes():
    rows = [[1, 0], [1, 0.2], [0.9, 0.1], [0, 0.1], [0.1, 0], [0, 0.2]]
    labels = [1, 1, 1, 0, 0, 0]
    _, coef = learn.fit(rows, labels)
    assert coef[0] > 1 and abs(coef[1]) < coef[0]


def test_weights_sum_to_100_and_negative_features_get_zero():
    w = learn.as_weights([2.0, -1.0, 2.0, 0, 0, 0, 0])
    assert round(sum(w.values())) == 100 and w["blast"] == 0 and w["hops"] == w["linked"] == 50


def test_needs_enough_verdicts_of_both_kinds(neo4j_driver, seeded, attack_ids):
    with neo4j_driver.session() as s:
        assert learn.from_verdicts(s)["ready"] is False
        noise = [r["id"] for r in s.run("MATCH (a:Alert) WHERE NOT a.id IN $ids RETURN a.id AS id LIMIT 6", ids=list(attack_ids))]
        s.run("UNWIND $ids AS id MATCH (a:Alert {id: id}) SET a.status = 'real'", ids=list(attack_ids))
        s.run("UNWIND $ids AS id MATCH (a:Alert {id: id}) SET a.status = 'false'", ids=noise)
        out = learn.from_verdicts(s)
    assert out["ready"] and out["verdicts"] == len(attack_ids) + 6 and out["applied"] is False
    assert round(sum(out["learned_weights"].values())) == 100
