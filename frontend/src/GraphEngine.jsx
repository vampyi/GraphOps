import { useEffect, useState } from "react";
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

  if (!data) return <div className="view-loading">Reading the graph…</div>;
  const sm = data.summary;

  return (
    <div className="graph-engine">
      <div className="ge-hero">
        <div className="ge-hero-main">
          <div className="ge-badge">Neo4j · Graph Data Science</div>
          <h2>Every question a SOC asks is one graph query.</h2>
          <p>GraphOps stores the whole organisation as one property graph, so tracing an attacker is a traversal,
             not a pile of table joins. The same graph answers "what can this reach", "what is the fastest route",
             "which node is the choke point" and "who holds access they never use".</p>
        </div>
        <div className="ge-stats">
          <div><b>{sm.entities}</b><span>users, groups & machines</span></div>
          <div><b>{sm.attack_edges}</b><span>attack-relevant edges</span></div>
          <div><b>{sm.relationships_total}</b><span>relationships in all</span></div>
        </div>
      </div>

      <div className="ge-proof panel">
        <div className="panel-head">
          <h2>Graph vs SQL, same question</h2>
          <small>“Can this machine reach that crown jewel?” — one Cypher traversal, timed live</small>
        </div>
        <div className="ge-proof-controls">
          <label>From <select value={src} onChange={(e) => setSrc(e.target.value)}>
            {uniq([src, ...nodes.sources]).map((n) => <option key={n} value={n}>{n}</option>)}
          </select></label>
          <label>to <select value={dst} onChange={(e) => setDst(e.target.value)}>
            {uniq([dst, ...nodes.targets]).map((n) => <option key={n} value={n}>{n}</option>)}
          </select></label>
          <button className="btn primary" disabled={running} onClick={() => run()}>{running ? "Running…" : "Run the query"}</button>
        </div>
        {proof && (
          <>
            <div className={`ge-verdict ${proof.reachable ? "bad" : "good"}`}>
              {proof.reachable
                ? <>Reachable in <b>{proof.hops} hop{proof.hops !== 1 ? "s" : ""}</b>: {proof.path.ids.map((id, i) => (
                    <span key={id}>{i > 0 && <em> {proof.path.types[i - 1]} </em>}<code>{id}</code></span>))}</>
                : <>No path. <b>{proof.src}</b> cannot reach <b>{proof.dst}</b> through attack edges.</>}
              <span className="ge-ms">{proof.cypher_ms} ms</span>
            </div>
            <div className="ge-cols">
              <div className="ge-code graph">
                <div className="ge-code-head"><span className="ge-tag ok">Neo4j · Cypher</span> one query, any depth</div>
                <pre>{proof.cypher}</pre>
              </div>
              <div className="ge-code sql">
                <div className="ge-code-head"><span className="ge-tag warn">SQL</span> {proof.reachable ? `${proof.hops} self-joins, fixed depth` : "a query per depth"}</div>
                <pre>{proof.sql}</pre>
              </div>
            </div>
            <div className="ge-note">{proof.sql_note}</div>
          </>
        )}
      </div>

      <div className="ge-algos">
        <h3>Graph algorithms, each doing a SOC job</h3>
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
        <h3>The one query behind each view</h3>
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
