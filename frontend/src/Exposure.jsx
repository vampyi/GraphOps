import { useEffect, useRef, useState } from "react";
import { Info } from "./parts.jsx";
import { getExposure, simulateExposure } from "./api.js";
import ExposureGraph from "./ExposureGraph.jsx";

// "1 path" / "2 paths": pick singular or plural wording for a count
const plural = (n, one, many = one + "s") => (n === 1 ? one : many);

// the edges and nodes still on a path after a simulated fix, so the graph can fade out everything cut
function remainingFromPaths(paths) {
  const edges = new Set(), nodes = new Set();
  (paths || []).forEach((p) => {
    p.nodes.forEach((n) => nodes.add(n));
    p.nodes.slice(1).forEach((n, i) => edges.add(`${p.nodes[i]}>${n}`));
  });
  return { edges, nodes };
}

// a number that tweens to its target, for the risk count dropping when a fix is applied
function AnimatedNumber({ value }) {
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    const start = performance.now(), a = from.current, b = value, dur = 600;
    let raf;
    const tick = (t) => {
      const k = Math.min(1, (t - start) / dur);
      setShown(Math.round(a + (b - a) * (1 - Math.pow(1 - k, 3))));
      if (k < 1) raf = requestAnimationFrame(tick); else from.current = b;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{shown}</>;
}

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

  if (loading || !data) return <div className="view-loading">Loading…</div>;

  const chokeIds = data.chokepoints.map((c) => c.id);
  const removedNodes = sim?.rec.kind === "node" ? [sim.rec.id] : [];
  const removedEdges = sim?.rec.kind === "cut" ? sim.rec.edges : [];
  const remaining = sim ? remainingFromPaths(sim.result.paths_after) : null;
  const reach = data.pairs;
  const current = sim ? sim.result.pairs_after : reach.reachable;

  return (
    <div className="exposure">
      <div className="exp-left">
        <div className="scope-switch">
          {SCOPES.map((s) => (
            <button key={s.id} className={scope === s.id ? "on" : ""} title={s.hint} onClick={() => setScope(s.id)}>{s.label}</button>
          ))}
        </div>

        <div className="exp-summary">
          <div className={`big-stat ${sim ? (current === 0 ? "cleared" : "reduced") : ""}`}>
            <div className="big-stat-v"><AnimatedNumber value={current} /></div>
            <div className="big-stat-l">
              {sim
                ? <>of {reach.possible} start-to-critical pairs still reachable after this fix{" "}<span className="cut-pill">−{sim.result.pairs_cut}</span></>
                : <>of {reach.possible} start-to-critical pairs reachable<Info text="Pairs of a starting machine and a critical asset that an attacker could connect, before any attack happens." /></>}
            </div>
          </div>
        </div>

        <h3>Fixes<Info text="Each fix is recomputed on the graph to count the start-to-critical pairs it really cuts. Select one to see it on the map." /></h3>
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
                  cuts {result?.pairs_cut ?? r.pairs_cut} of {result?.pairs_before ?? reach.reachable} {plural(result?.pairs_before ?? reach.reachable, "pair")}
                  {r.kind === "node" ? ` · ${r.pairs_through} through ${r.id}` : ""}
                </div>
                {r.kind === "cut" && (
                  <ul className="rec-edges">{r.edges.map((e, j) => <li key={j}>{e.action}</li>)}</ul>
                )}
                {active && <div className="rec-after">{result.pairs_after === 0 ? "No pairs remain reachable" : `${result.pairs_after} ${plural(result.pairs_after, "pair")} still reachable`}</div>}
              </li>
            );
          })}
        </ul>

        <h3>Choke points<Info text="Machines or accounts that many attack paths pass through. Securing one cuts every path through it." /></h3>
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
          <small>start → critical asset</small>
          <Info text="Starting machines on the left, critical assets on the right. Each step is tagged with its MITRE ATT&CK technique." />
        </div>
        {data.nodes.length === 0
          ? <div className="view-loading">No paths to a critical asset</div>
          : <div className="exp-graph-wrap">
              <ExposureGraph data={data} chokeIds={chokeIds} removedNodes={removedNodes} removedEdges={removedEdges} remaining={remaining} />
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
