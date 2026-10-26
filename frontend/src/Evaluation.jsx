import { useEffect, useState } from "react";
import { getEvaluation, getLearning } from "./api.js";

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
      <section className="panel evalv-intro">
        <h2>Does GraphOps find the attack sooner than sorting by severity?</h2>
        <p>
          Every day we load comes with labels saying which alerts belong to the attack. The ranker never sees those labels.
          Here we compare two orders against them: GraphOps' score, and the tools' own severity, which is how most consoles sort alerts.
        </p>
        <p>
          The <b>sample day</b> is the one the weights were set on, so it is not a fair test. The other days in the <b>Day</b> menu
          are held-out attacks the weights were never tuned on, each built around a known weakness. Pick one there to evaluate it.
        </p>
      </section>

      {data && (
        <section className="panel evalv-result">
          <div className="evalv-title">{dayName || "Loaded day"} <small>{data.total} alerts, {data.attack} belong to the attack</small></div>
          <div className="evalv-grid">
            <Column title="GraphOps" badge="ranked by graph position" win m={data.graphops} />
            <Column title="Severity only" badge="what most tools do" m={data.severity} />
          </div>
          <p className="evalv-note">
            Average precision is 1.0 when every attack alert comes before every other alert. The top-5 share can be at most the number of attack alerts divided by 5. Severity ties are broken by time, oldest first.
            These are small, synthetic days written by us; results on real data are untested.
          </p>
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
      <div className="evalv-title">Learning from analyst verdicts <small>{l.verdicts} verdicts so far: {l.real} real, {l.not_real} benign or false</small></div>
      <p className="evalv-p">
        Each time an analyst marks an alert real, benign or a false alarm, GraphOps can learn how much each ranking question should
        count, with a small, explainable model (logistic regression). The learned weights are shown here next to the hand-set ones.
        They are not switched on automatically.
      </p>
      {!l.ready
        ? <p className="evalv-p dim">It needs at least {l.min_verdicts} verdicts, with at least {l.min_per_class} real and {l.min_per_class} benign or false. Mark alerts in Triage to add them.</p>
        : (
          <table className="learn-table">
            <thead><tr><th>Ranking question</th><th>Hand-set weight</th><th>Learned from verdicts</th></tr></thead>
            <tbody>
              {Object.keys(FEATURE_LABEL).map((f) => (
                <tr key={f}><td>{FEATURE_LABEL[f]}</td><td>{l.hand_weights[f]}</td><td>{l.learned_weights[f]}{l.pointed_away.includes(f) ? " (pointed away from real attacks)" : ""}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      <p className="evalv-note">
        We tested this on our six labelled days, each time learning from the other five. The learned weights ranked the attacks no better than the hand-set weights:
        equal on three days, slightly worse on three. Every learned version gave the tool's own severity a weight of zero.
        That is why the model stays off until real analyst verdicts exist.
      </p>
    </section>
  );
}

function Column({ title, badge, m, win }) {
  return (
    <div className={`evalv-col ${win ? "win" : ""}`}>
      <div className="evalv-col-h">{title}<span className="eval-badge">{badge}</span></div>
      <Metric v={m.last_attack_rank ? `top ${m.last_attack_rank}` : "—"} l="every attack alert ranks within" />
      <Metric v={m.false_before_first} l="other alerts read before the first attack alert" />
      <Metric v={m.precision_at_5} l="share of the top 5 that belong to the attack" />
      <Metric v={m.average_precision} l="average precision" />
    </div>
  );
}

function Metric({ v, l }) {
  return <div className="eval-metric"><span className="eval-v">{v}</span><span className="eval-l">{l}</span></div>;
}
