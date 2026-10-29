import { useEffect, useState } from "react";
import { Info } from "./parts.jsx";
import { getExposure, getGraphAlgorithms, getGraphFull, getReachabilityProof } from "./api.js";
import GraphMap, { MODES } from "./GraphMap.jsx";
import { Shape } from "./RingGraph.jsx";

const KIND = { User: "User", Group: "Group", Computer: "Computer", CloudResource: "Cloud resource", ServiceIdentity: "Service identity",
  AIAgent: "AI agent", Tool: "Agent tool", Software: "Software", Internet: "Internet" };

// the Neo4j story, made clickable: one graph query per SOC question, the algorithms in play, and a live
// side-by-side of the same question in Cypher and in SQL.
export default function GraphEngine({ onError }) {
  const [data, setData] = useState(null);
  const [nodes, setNodes] = useState({ sources: [], targets: [] });
  const [src, setSrc] = useState("laptop-42");
  const [dst, setDst] = useState("customer-db");
  const [proof, setProof] = useState(null);
  const [running, setRunning] = useState(false);
  const [openCypher, setOpenCypher] = useState(null);
  const [graph, setGraph] = useState(null);
  const [mode, setMode] = useState("community");
  const [showPath, setShowPath] = useState(false);

  useEffect(() => {
    getGraphAlgorithms().then(setData).catch((e) => onError(e.message));
    getGraphFull().then(setGraph).catch(() => {});
    getExposure("all").then((e) => {
      setNodes({ sources: e.sources, targets: e.targets });
      if (e.sources.length && !e.sources.includes("laptop-42")) setSrc(e.sources[0]);
      if (e.targets.length && !e.targets.includes("customer-db")) setDst(e.targets[0]);
    }).catch(() => {});
    run("laptop-42", "customer-db");
  }, []); // eslint-disable-line

  async function run(s = src, d = dst) {
    setRunning(true);
    try { setProof(await getReachabilityProof(s, d)); } catch (e) { onError(e.message); }
    setRunning(false);
  }

  if (!data) return <div className="view-loading">Loading…</div>;
  const sm = data.summary;

  return (
    <div className="graph-engine">
      <div className="ge-hero">
        <div className="ge-hero-main">
          <div className="ge-badge">Neo4j</div>
          <h2>The graph<Info text="Users, groups, machines, permissions and logins in one Neo4j graph. Reachability, attack paths, choke points and unused access are each answered by a graph query or algorithm." /></h2>
        </div>
        <div className="ge-stats">
          <div><b>{sm.entities}</b><span>systems, people & AI agents</span></div>
          <div><b>{graph ? new Set(graph.edges.map((e) => e.type)).size : "–"}</b><span>relationship types</span></div>
          <div><b>{sm.attack_edges}</b><span>attack-relevant edges</span></div>
          <div><b>{sm.relationships_total}</b><span>relationships in all</span></div>
        </div>
      </div>

      {graph && (
        <div className="ge-main">
          <div className="panel ge-map">
            <div className="panel-head">
              <h2>Live graph</h2>
              <small>{graph.nodes.length} nodes · {graph.edges.length} relationships</small>
              <Info text={MODES.find((m) => m.id === mode).tip} />
              <div className="ge-modes">
                {MODES.map((m) => <button key={m.id} className={mode === m.id ? "on" : ""} onClick={() => setMode(m.id)}>{m.label}</button>)}
              </div>
            </div>
            <div className="ge-map-wrap"><GraphMap data={graph} mode={mode} path={showPath && proof?.reachable ? proof.path : null} /></div>
            <div className="ge-map-foot">
              {mode === "zones"
                ? <span>Internet · on-premises · cloud, left to right. Red = critical asset.</span>
                : <span><b>{MODES.find((m) => m.id === mode).algo}</b> · {graph.gds ? "ran on Neo4j Graph Data Science" : "this database has no Graph Data Science (AuraDB Free), so it ran in Python (networkx) on the graph read from Neo4j"}</span>}
              <span className="gm-key"><i className="attack" />attack step <i className="other" />other relationship</span>
            </div>
          </div>

          <div className="panel ge-model">
            <div className="panel-head">
              <h2>Data model</h2>
              <small>what is in the graph</small>
              <Info text="Every kind of node and every kind of relationship in the loaded graph, with counts. Relationships marked with a technique are attack steps." />
            </div>
            <div className="ge-kinds">
              {Object.entries(graph.kinds).sort((a, b) => b[1] - a[1]).map(([k, c]) => (
                <span key={k} className="ge-kind">
                  <svg viewBox="0 0 24 24"><Shape kind={k} x={12} y={12} r={6} className="ge-kind-shape" /></svg>
                  {KIND[k] || k}<b>{c}</b>
                </span>
              ))}
            </div>
            <ul className="ge-schema">
              {graph.schema.map((r) => (
                <li key={`${r.src}-${r.type}-${r.dst}`}>
                  <span className="ge-rel"><em>{KIND[r.src] || r.src}</em><code>{r.type}</code><em>{KIND[r.dst] || r.dst}</em></span>
                  {r.technique && <span className="ge-tech" title={r.tactic || ""}>{r.technique}</span>}
                  <b>{r.count}</b>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="ge-proof panel">
        <div className="panel-head">
          <h2>Path finder</h2>
          <small>shortest attack path between two systems, drawn on the graph above</small>
        </div>
        <div className="ge-proof-controls">
          <label>From <select value={src} onChange={(e) => setSrc(e.target.value)}>
            {uniq([src, ...nodes.sources]).map((n) => <option key={n} value={n}>{n}</option>)}
          </select></label>
          <label>to <select value={dst} onChange={(e) => setDst(e.target.value)}>
            {uniq([dst, ...nodes.targets]).map((n) => <option key={n} value={n}>{n}</option>)}
          </select></label>
          <button className="btn primary" disabled={running} onClick={() => { run(); setShowPath(true); }}>{running ? "Finding…" : "Find path"}</button>
          {showPath && <button className="btn ghost small" onClick={() => setShowPath(false)}>Clear from graph</button>}
        </div>
        {proof && (
          <>
            <div className={`ge-verdict ${proof.reachable ? "bad" : "good"}`}>
              {proof.reachable
                ? <>Reachable in <b>{proof.hops} hop{proof.hops !== 1 ? "s" : ""}</b>: {proof.path.ids.map((id, i) => (
                    <span key={id}>{i > 0 && <em> {proof.path.types[i - 1]} </em>}<code>{id}</code></span>))}</>
                : <>No attack path from <b>{proof.src}</b> to <b>{proof.dst}</b></>}
              <span className="ge-ms">{proof.cypher_ms} ms</span>
            </div>
            <details className="ge-query-inline">
              <summary>Query</summary>
              <pre>{proof.cypher}</pre>
            </details>
          </>
        )}
      </div>

      <div className="ge-algos">
        <h3>Algorithms<Info text="Engine shows where each runs: Neo4j Graph Data Science where installed, otherwise Cypher or Python (networkx)." /></h3>
        <div className="algo-grid">
          {data.algorithms.map((a) => (
            <div key={a.algorithm} className="algo-card">
              <div className="algo-top">
                <span className="algo-name">{a.algorithm}</span>
                <span className={`algo-engine ${a.gds && data.gds ? "gds" : ""}`}>{a.gds && !data.gds ? "networkx (no GDS here)" : a.engine}</span>
              </div>
              <div className="algo-q">{a.question}</div>
              <div className="algo-r">{a.result}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="ge-queries">
        <h3>Queries behind each view</h3>
        {Object.entries(sm.cypher).map(([key, q]) => (
          <div key={key} className={`ge-query ${openCypher === key ? "open" : ""}`}>
            <button className="ge-query-head" onClick={() => setOpenCypher(openCypher === key ? null : key)}>
              <span>{q.question}</span><span className="chev">{openCypher === key ? "–" : "+"}</span>
            </button>
            {openCypher === key && (
              <div className="ge-query-body">
                <pre>{q.cypher}</pre>
                <div className="ge-why">{q.why_graph}</div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const uniq = (arr) => [...new Set(arr)];
