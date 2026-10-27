import { useEffect, useState } from "react";
import { getEvaluation, getLearning } from "./api.js";
import { Info } from "./parts.jsx";

// ranking quality for the loaded day: GraphOps order vs sorting by the tools' own severity, against labels the
// ranker never sees. switching the day in the top bar evaluates another labelled day.
export default function Evaluation({ onError, dayName }) {
  const [data, setData] = useState(null);
  const [learning, setLearning] = useState(null);
  useEffect(() => {
    getEvaluation().then(setData).catch((e) => { setData(null); onError(`Could not load the evaluation: ${e.message}`); });
    getLearning().then(setLearning).catch(() => setLearning(null));
  }, [dayName]); // eslint-disable-line

  return (
    <main className="evalv">
      {data && (
        <section className="panel evalv-result">
          <div className="evalv-title">
            Ranking quality · {dayName || "Loaded scenario"}
            <small>{data.total} alerts · {data.attack} in the attack</small>
            <Info text="Each scenario comes with labels marking the attack's alerts. The ranker never sees them. The weights were set on the customer-database scenario; the others are held-out attacks, each built around a known weakness. All scenarios are synthetic." />
          </div>
          <div className="evalv-grid">
            <Column title="GraphOps" badge="graph position" win m={data.graphops} />
            <Column title="Severity" badge="typical console" m={data.severity} />
          </div>
        </section>
      )}

      {learning && <Learning l={learning} />}
    </main>
  );
}

const FEATURE_LABEL = {
  hops: "Close to a critical asset", blast: "Critical assets within 3 hops", linked: "Linked to other alerts",
  never_taken: "Route never used before", stages: "Follows attack stages in order", choke: "Sits on a choke point",
  severity: "Tool's own severity",
};

function Learning({ l }) {
  return (
    <section className="panel evalv-learn">
      <div className="evalv-title">
        Learned weights
        <small>{l.verdicts} verdicts · {l.real} real · {l.not_real} benign or false</small>
        <Info text="A logistic regression learns from analyst verdicts how much each question should count. Not applied: on six synthetic days it ranked no better than the hand-set weights, and it gave severity zero weight." />
      </div>
      {!l.ready
        ? <p className="evalv-p dim">Needs {l.min_verdicts} verdicts, at least {l.min_per_class} real and {l.min_per_class} benign or false. Mark alerts in Triage.</p>
        : (
          <table className="learn-table">
            <thead><tr><th>Question</th><th>Hand-set</th><th>Learned</th></tr></thead>
            <tbody>
              {Object.keys(FEATURE_LABEL).map((f) => (
                <tr key={f}><td>{FEATURE_LABEL[f]}</td><td>{l.hand_weights[f]}</td><td>{l.learned_weights[f]}</td></tr>
              ))}
            </tbody>
          </table>
        )}
    </section>
  );
}

function Column({ title, badge, m, win }) {
  return (
    <div className={`evalv-col ${win ? "win" : ""}`}>
      <div className="evalv-col-h">{title}<span className="eval-badge">{badge}</span></div>
      <Metric v={m.last_attack_rank ? `top ${m.last_attack_rank}` : "—"} l="all attack alerts within" />
      <Metric v={m.false_before_first} l="read before the first attack alert" />
      <Metric v={m.precision_at_5} l="precision@5" tip="Share of the top 5 that belong to the attack. At most the number of attack alerts divided by 5." />
      <Metric v={m.average_precision} l="average precision" tip="1.0 when every attack alert comes before every other alert." />
    </div>
  );
}

function Metric({ v, l, tip }) {
  return <div className="eval-metric"><span className="eval-v">{v}</span><span className="eval-l">{l}{tip && <Info text={tip} />}</span></div>;
}
