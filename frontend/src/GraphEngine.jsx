import { lazy, Suspense, useEffect, useState } from "react";
import { Info } from "./parts.jsx";
import { getExposure, getGraphAlgorithms, getGraphFull, getReachabilityProof } from "./api.js";
import GraphMap, { distances, KIND_COLOR, MODES } from "./GraphMap.jsx";

// neo4j's visualization library, loaded only when the backend is on neo4j aura (its licence covers aura only)
const NvlMap = lazy(() => import("./NvlMap.jsx"));

function useDark() {
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme !== "light");
  useEffect(() => {
    const el = document.documentElement;
    const mo = new MutationObserver(() => setDark(el.dataset.theme !== "light"));
    mo.observe(el, { attributes: true, attributeFilter: ["data-theme"] });
    return () => mo.disconnect();
  }, []);
  return dark;
}
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
  const [mode, setMode] = useState("types");
  const dark = useDark();
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

      {graph && <Facts graph={graph} mode={mode} />}

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
            <div className="ge-map-wrap">
              {graph.aura
                ? <Suspense fallback={<div className="view-loading">Loading graph…</div>}>
                    <NvlMap data={graph} mode={mode} dark={dark} path={showPath && proof?.reachable ? proof.path : null} />
                  </Suspense>
                : <GraphMap data={graph} mode={mode} path={showPath && proof?.reachable ? proof.path : null} />}
            </div>
            <div className="ge-map-foot">
              {mode === "types" || mode === "zones"
                ? <span>{graph.aura ? "Drawn with Neo4j Visualization Library (NVL). Drag, zoom, click a node." : mode === "zones" ? "Internet · on-premises · cloud, left to right." : "Colour = node label."} Red = critical asset.</span>
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
                  <svg viewBox="0 0 24 24" style={{ fill: KIND_COLOR[k] }}><Shape kind={k} x={12} y={12} r={6} className="ge-kind-shape" /></svg>
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

const top = (nodes, key, k = 2) => nodes.filter((n) => !n.critical && n[key] != null).sort((a, b) => b[key] - a[key]).slice(0, k).map((n) => n.id);

// the four things the graph says at first sight, and one line on what the selected view shows
function Facts({ graph, mode }) {
  const dist = distances(graph);
  const crit = graph.nodes.filter((n) => n.critical).length;
  const reach = graph.nodes.filter((n) => !n.critical && dist[n.id] != null).length;
  const agents = graph.nodes.filter((n) => n.kind === "AIAgent");
  const agentsOnRoute = agents.filter((n) => dist[n.id] != null).length;
  const chokes = top(graph.nodes, "choke");
  const influential = top(graph.nodes, "pagerank");
  const communities = new Set(graph.nodes.map((n) => n.community).filter((c) => c != null)).size;
  const cloudOnRoute = graph.nodes.filter((n) => n.location === "cloud" && !n.critical && dist[n.id] != null).length;
  const line = {
    types: "Read left to right: each column is one attack step closer to a critical asset.",
    community: `${communities} groups of machines and people that normally work together. A login that crosses colours is lateral movement.`,
    pagerank: `${influential.join(" and ")} are reached by the most attack routes, so they would cause the most damage if compromised.`,
    choke: `${chokes.join(" and ")} sit on the most attack paths. Securing them cuts the most routes.`,
    zones: `${cloudOnRoute} cloud system${cloudOnRoute === 1 ? "" : "s"} and the internet have routes into critical assets.`,
  }[mode];
  return (
    <div className="ge-facts">
      <div className="ge-fact crit"><b>{crit}</b><span>critical assets</span></div>
      <div className="ge-fact"><b>{reach}</b><span>systems with an attack route to one</span></div>
      <div className="ge-fact"><b>{chokes[0] || "–"}</b><span>top choke point</span></div>
      <div className="ge-fact"><b>{agentsOnRoute} of {agents.length}</b><span>AI agents on an attack route</span></div>
      <p className="ge-line">{line}</p>
    </div>
  );
}
