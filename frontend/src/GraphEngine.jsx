import { lazy, Suspense, useEffect, useState } from "react";
import { Info } from "./parts.jsx";
import { getExposure, getGraphAlgorithms, getGraphFull, getReachabilityProof } from "./api.js";
import GraphMap, { COMMUNITY_COLOR, distances, KIND_COLOR, LOCATION_COLOR, MODES, topBy } from "./GraphMap.jsx";

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
import Proof from "./Proof.jsx";
import Sources from "./Sources.jsx";

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

      <Sources />

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

          <ViewPanel graph={graph} mode={mode} />
        </div>
      )}

      <Proof />

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
    types: "Each group is one kind of node; red is the critical assets. Lines are attack steps between groups.",
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

// the right-hand panel follows the selected view: the data model for node types, the ranking behind influence
// and choke points, the members of each community, or the count per location
function ViewPanel({ graph, mode }) {
  const empty = !graph.nodes.some((n) => n.pagerank != null);
  const head = (title, sub, tip) => (
    <div className="panel-head"><h2>{title}</h2><small>{sub}</small><Info text={tip} /></div>
  );
  if (mode === "types") return (
    <div className="panel ge-model">
      {head("Data model", "what is in the graph", "Every kind of node and every kind of relationship in the loaded graph, with counts. Relationships marked with a technique are attack steps.")}
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
  );
  if (empty) return (
    <div className="panel ge-model">{head("Scores", "recomputing", "The graph was just reloaded, for example by a live stream. Scores appear once the analysis has run.")}
      <p className="ge-empty">Scores are being recomputed. Refresh in a few seconds.</p></div>
  );
  if (mode === "pagerank" || mode === "choke") {
    const key = mode === "pagerank" ? "pagerank" : "choke";
    const rows = topBy(graph.nodes, key, 10);
    return (
      <div className="panel ge-model">
        {mode === "pagerank"
          ? head("Most influential", "PageRank", "PageRank on the attack graph: a node scores high when many attack routes lead into it. Ringed on the graph: the top 6. Scores are relative to the highest.")
          : head("Top choke points", "betweenness", "Betweenness centrality on the attack graph: how many shortest attack paths pass through a node. Securing a high one cuts many paths. Ringed on the graph: the top 6.")}
        <ol className="ge-rank">
          {rows.map((n, i) => (
            <li key={n.id} className={i < 6 ? "top" : ""}>
              <span className="ge-rank-n">{i + 1}</span>
              <span className="ge-rank-id"><i style={{ background: KIND_COLOR[n.kind] }} />{n.id}<small>{KIND[n.kind] || n.kind}</small></span>
              <span className={`ge-rank-bar ${mode}`}><i style={{ width: `${Math.round(n[key] * 100)}%` }} /></span>
              <b>{n[key].toFixed(2)}</b>
            </li>
          ))}
        </ol>
      </div>
    );
  }
  if (mode === "community") {
    const groups = {};
    graph.nodes.filter((n) => !n.critical).forEach((n) => (groups[n.community ?? 0] ||= []).push(n.id));
    const list = Object.entries(groups).filter(([c]) => c !== "0").sort((a, b) => b[1].length - a[1].length);
    return (
      <div className="panel ge-model">
        {head("Communities", "Louvain", "Louvain groups machines and people by who logs in where. Each colour is a group that normally works together; a login across groups looks like lateral movement. Groups, cloud resources and AI agents have no logins of their own, so they are shown as No activity.")}
        <ul className="ge-comms">
          {list.map(([c, ids]) => (
            <li key={c}>
              <i style={{ background: COMMUNITY_COLOR[(c - 1) % COMMUNITY_COLOR.length] }} />
              <span>{ids.slice(0, 4).join(", ")}{ids.length > 4 ? ` +${ids.length - 4}` : ""}</span>
              <b>{ids.length}</b>
            </li>
          ))}
          {groups[0] && <li className="muted"><i /><span>No activity: {groups[0].length} groups, cloud and agent nodes</span><b>{groups[0].length}</b></li>}
        </ul>
      </div>
    );
  }
  const by = (loc) => graph.nodes.filter((n) => n.location === loc);
  return (
    <div className="panel ge-model">
      {head("Where things live", "on-premises, cloud, internet", "Each node's location. Attack steps that cross from one group to another are where on-premises access turns into cloud access.")}
      <ul className="ge-comms">
        {[["external", "Internet"], ["onprem", "On-premises"], ["cloud", "Cloud"]].map(([loc, label]) => (
          <li key={loc}><i style={{ background: LOCATION_COLOR[loc] }} /><span>{label}: {by(loc).slice(0, 4).map((n) => n.id).join(", ")}{by(loc).length > 4 ? "…" : ""}</span><b>{by(loc).length}</b></li>
        ))}
      </ul>
    </div>
  );
}
