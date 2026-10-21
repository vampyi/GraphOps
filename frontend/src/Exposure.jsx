import { useEffect, useState } from "react";
import { getExposure, simulateExposure } from "./api.js";
import ExposureGraph from "./ExposureGraph.jsx";

const SCOPES = [
  { id: "low_trust", label: "From low-trust machines", hint: "Guest, intern and internet-facing machines" },
  { id: "all", label: "From any machine or account", hint: "If anything at all were compromised" },
];

export default function Exposure({ onError }) {
  const [scope, setScope] = useState("low_trust");
  const [data, setData] = useState(null);
  const [sim, setSim] = useState(null);       // {rec, result}
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true); setSim(null);
    getExposure(scope).then((d) => { setData(d); setLoading(false); })
      .catch((e) => { onError(e.message); setLoading(false); });
  }, [scope]); // eslint-disable-line

  const runSim = async (rec) => {
    if (sim?.rec === rec) { setSim(null); return; }
    try {
      const body = rec.kind === "cut"
        ? { scope, edges: rec.edges.map((e) => ({ src: e.src, dst: e.dst })) }
        : { scope, nodes: [rec.id] };
      setSim({ rec, result: await simulateExposure(body) });
    } catch (e) { onError(e.message); }
  };

  if (loading || !data) return <div className="view-loading">Mapping attack paths…</div>;

  const chokeIds = data.chokepoints.map((c) => c.id);
  const removedNodes = sim?.rec.kind === "node" ? [sim.rec.id] : [];
  const removedEdges = sim?.rec.kind === "cut" ? sim.rec.edges : [];
  const reach = data.pairs;

  return (
    <div className="exposure">
      <div className="exp-left">
        <div className="scope-switch">
          {SCOPES.map((s) => (
            <button key={s.id} className={scope === s.id ? "on" : ""} title={s.hint} onClick={() => setScope(s.id)}>{s.label}</button>
          ))}
        </div>

        <div className="exp-summary">
          <div className="big-stat">
            <div className="big-stat-v">{reach.reachable}</div>
            <div className="big-stat-l">source → critical pairs an attacker could reach, of {reach.possible} possible</div>
          </div>
        </div>

        <h3>Fix the choke points</h3>
        <p className="muted-p">Each fix is measured on the graph: how many of the {reach.reachable} paths it actually cuts. Click one to see it on the map.</p>
        <ul className="recs">
          {data.recommendations.map((r, i) => {
            const active = sim?.rec === r;
            const result = active ? sim.result : null;
            return (
              <li key={i} className={active ? "on" : ""} onClick={() => runSim(r)}>
                <div className="rec-top">
                  <span className="rec-title">{r.title}</span>
                  <span className="rec-cut">{Math.round((result?.share_cut ?? r.share_cut) * 100)}%</span>
                </div>
                <div className="rec-sub">
                  cuts {result?.pairs_cut ?? r.pairs_cut} of {result?.pairs_before ?? reach.reachable} paths
                  {r.kind === "node" ? ` · ${r.pairs_through} paths pass through ${r.id}` : ""}
                </div>
                {r.kind === "cut" && (
                  <ul className="rec-edges">{r.edges.map((e, j) => <li key={j}>{e.action}</li>)}</ul>
                )}
                {active && <div className="rec-after">{result.pairs_after === 0 ? "No path from the low-trust zone to a critical asset remains." : `${result.pairs_after} path(s) would remain.`}</div>}
              </li>
            );
          })}
        </ul>

        <h3>Choke points</h3>
        <table className="choke-table">
          <thead><tr><th>Node</th><th>Paths</th><th>Pairs</th></tr></thead>
          <tbody>
            {data.chokepoints.slice(0, 8).map((c) => (
              <tr key={c.id}><td><span className={`dot ${c.kind}`} />{c.id}</td><td>{c.paths_through}</td><td>{c.pairs_through}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="exp-main panel">
        <div className="panel-head">
          <h2>Attack map</h2>
          <small>low-trust machines on the left, critical assets on the right, each step tagged with its ATT&CK technique</small>
        </div>
        {data.nodes.length === 0
          ? <div className="view-loading">No path from this starting point to a critical asset. That is the goal.</div>
          : <div className="exp-graph-wrap">
              <ExposureGraph data={data} chokeIds={chokeIds} removedNodes={removedNodes} removedEdges={removedEdges} />
            </div>}
        <div className="legend">
          <span><i className="lg source" />start</span>
          <span><i className="lg mid" />step</span>
          <span><i className="lg choke" />choke point</span>
          <span><i className="lg critical" />critical asset</span>
          {sim && <span className="legend-cut">dashed = removed by the selected fix</span>}
          <span className="shapes">● user ■ group ◆ computer</span>
        </div>
      </div>
    </div>
  );
}
