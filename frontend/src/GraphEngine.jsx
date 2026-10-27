import { useEffect, useState } from "react";
import { Info } from "./parts.jsx";
import { getExposure, getGraphAlgorithms, getReachabilityProof } from "./api.js";

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

  useEffect(() => {
    getGraphAlgorithms().then(setData).catch((e) => onError(e.message));
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
          <div><b>{sm.entities}</b><span>users, groups & machines</span></div>
          <div><b>{sm.attack_edges}</b><span>attack-relevant edges</span></div>
          <div><b>{sm.relationships_total}</b><span>relationships in all</span></div>
        </div>
      </div>

      <div className="ge-proof panel">
        <div className="panel-head">
          <h2>Path finder</h2>
          <small>shortest attack path between two systems</small>
        </div>
        <div className="ge-proof-controls">
          <label>From <select value={src} onChange={(e) => setSrc(e.target.value)}>
            {uniq([src, ...nodes.sources]).map((n) => <option key={n} value={n}>{n}</option>)}
          </select></label>
          <label>to <select value={dst} onChange={(e) => setDst(e.target.value)}>
            {uniq([dst, ...nodes.targets]).map((n) => <option key={n} value={n}>{n}</option>)}
          </select></label>
          <button className="btn primary" disabled={running} onClick={() => run()}>{running ? "Finding…" : "Find path"}</button>
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
                <span className={`algo-engine ${a.gds ? "gds" : ""}`}>{a.engine}</span>
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
