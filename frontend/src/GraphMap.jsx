import { useMemo, useState } from "react";
import { Shape } from "./RingGraph.jsx";

const W = 960;
const H = 600;
// where each location sits across the picture: outside on the left, on-premises in the middle, cloud on the right
const ZONE_X = { external: 0.1, onprem: 0.48, cloud: 0.86 };
// each location keeps its nodes inside its own band, so the left-to-right reading always holds
const BAND = { external: [0.05, 0.17], onprem: [0.22, 0.72], cloud: [0.78, 0.95] };
const COMMUNITY = ["#14b8a6", "#6366f1", "#f59e0b", "#ec4899", "#22c55e", "#0ea5e9", "#a855f7", "#ef4444", "#84cc16", "#f97316", "#06b6d4", "#e11d48"];

// node colours from the neo4j browser palette, shared with the nvl view, so the graph reads like neo4j.
// red stays reserved for critical assets.
export const KIND_COLOR = {
  Computer: "#57C7E3", User: "#F79767", Group: "#C990C0", AIAgent: "#8DCC93", Tool: "#FFC454",
  CloudResource: "#4C8EDA", ServiceIdentity: "#569480", Software: "#D9C8AE", Internet: "#ECB5C9",
};

// columns by attack distance: how many attack steps each node is from the nearest critical asset, worked out
// backwards from the critical assets along the attack steps. critical assets sit on the right, nodes with no
// route to one on the left, so the picture reads left to right as the attacker's way in.
export const COLUMNS = [
  { key: "none", label: "No route" }, { key: 4, label: "4+ steps" }, { key: 3, label: "3 steps" },
  { key: 2, label: "2 steps" }, { key: 1, label: "1 step" }, { key: 0, label: "Critical assets" },
];
export function distances(data) {
  const into = {};
  data.edges.filter((e) => e.attack).forEach((e) => (into[e.dst] ||= []).push(e.src));
  const dist = {};
  const queue = data.nodes.filter((n) => n.critical).map((n) => n.id);
  queue.forEach((id) => (dist[id] = 0));
  for (let i = 0; i < queue.length; i++) {
    for (const src of into[queue[i]] || []) {
      if (dist[src] == null) { dist[src] = dist[queue[i]] + 1; queue.push(src); }
    }
  }
  return dist;
}

export const MODES = [
  { id: "types", label: "Node types", algo: "Labels",
    tip: "Colour = the kind of node (its Neo4j label), as in Neo4j Bloom. Red = critical asset." },
  { id: "community", label: "Communities", algo: "Louvain",
    tip: "Colour = activity community found by Louvain. Machines and people that normally work together share a colour, so a login that crosses colours looks like lateral movement." },
  { id: "pagerank", label: "Influence", algo: "PageRank",
    tip: "Size = PageRank on the attack graph. Bigger nodes are reached by more attack routes and would cause the most disruption if compromised." },
  { id: "choke", label: "Choke points", algo: "Betweenness",
    tip: "Size and ring = betweenness centrality. These nodes sit on the most attack paths; securing one cuts every path through it." },
  { id: "zones", label: "On-prem, cloud, AI", algo: "Location",
    tip: "Where each node lives: the internet on the left, on-premises in the middle, cloud on the right. AI agents are hexagons." },
];

// fruchterman-reingold: nodes push apart, connections pull together, a pull towards each node's location
// column keeps internet, on-premises and cloud apart, and a cooling step limit settles it. seeded, so the same
// graph always lands in the same place.
function layout(nodes, edges) {
  let seed = 7;
  const rand = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
  const zx = (n) => W * (ZONE_X[n.location] ?? 0.5);
  const p = nodes.map((n) => ({ id: n.id, x: zx(n) + (rand() - 0.5) * 160, y: H / 2 + (rand() - 0.5) * 360, zx: zx(n), loc: n.location }));
  const at = Object.fromEntries(p.map((q, i) => [q.id, i]));
  const links = edges.map((e) => [at[e.src], at[e.dst]]).filter(([a, b]) => a != null && b != null && a !== b);
  const k = 0.6 * Math.sqrt((W * H) / Math.max(nodes.length, 1));
  const steps = 500;
  for (let it = 0; it < steps; it++) {
    const temp = (W / 10) * (1 - it / steps) + 0.5;
    const dx = new Float64Array(p.length), dy = new Float64Array(p.length);
    for (let i = 0; i < p.length; i++) {
      for (let j = i + 1; j < p.length; j++) {
        const ex = p[i].x - p[j].x, ey = p[i].y - p[j].y;
        const d = Math.max(Math.hypot(ex, ey), 0.01);
        const f = (k * k) / d / d;
        dx[i] += ex * f; dy[i] += ey * f; dx[j] -= ex * f; dy[j] -= ey * f;
      }
    }
    for (const [a, b] of links) {
      const ex = p[a].x - p[b].x, ey = p[a].y - p[b].y;
      const d = Math.max(Math.hypot(ex, ey), 0.01);
      const f = d / k;
      dx[a] -= ex * f; dy[a] -= ey * f; dx[b] += ex * f; dy[b] += ey * f;
    }
    for (let i = 0; i < p.length; i++) {
      dx[i] += (p[i].zx - p[i].x) * 0.6;
      dy[i] += (H / 2 - p[i].y) * 0.3;
      const d = Math.max(Math.hypot(dx[i], dy[i]), 0.01), step = Math.min(d, temp);
      const [lo, hi] = BAND[p[i].loc] || BAND.onprem;
      p[i].x = Math.min(W * hi, Math.max(W * lo, p[i].x + (dx[i] / d) * step));
      p[i].y = Math.min(H - 30, Math.max(36, p[i].y + (dy[i] / d) * step));
    }
  }
  return Object.fromEntries(p.map((q) => [q.id, q]));
}

function radius(n, mode) {
  if (mode === "pagerank") return 6 + 14 * (n.pagerank ?? 0);
  if (mode === "choke") return 6 + 14 * (n.choke ?? 0);
  return n.critical ? 11 : 8;
}

function fill(n, mode) {
  if (n.critical) return "var(--red)";
  if (mode === "community") return n.community ? COMMUNITY[(n.community - 1) % COMMUNITY.length] : "var(--node)";
  if (mode === "types") return KIND_COLOR[n.kind] || "var(--node)";
  if (mode === "zones") return n.location === "cloud" ? "var(--cloud)" : n.location === "external" ? "var(--amber)" : "var(--teal)";
  return "var(--teal)";
}

// the whole graph, drawn once. mode switches what colour and size mean; path draws one route in red on top.
export default function GraphMap({ data, mode, path }) {
  const [hover, setHover] = useState(null);
  const pos = useMemo(() => layout(data.nodes, data.edges), [data]);
  const onPath = new Set(path?.ids || []);
  const pathEdge = new Set((path?.ids || []).slice(1).map((id, i) => `${path.ids[i]}>${id}`));
  const top = new Set([...data.nodes]
    .filter((n) => (mode === "pagerank" ? n.pagerank : mode === "choke" ? n.choke : 0) > 0)
    .sort((a, b) => (mode === "pagerank" ? b.pagerank - a.pagerank : b.choke - a.choke)).slice(0, 6).map((n) => n.id));
  const linked = new Set();
  if (hover) data.edges.forEach((e) => { if (e.src === hover || e.dst === hover) { linked.add(e.src); linked.add(e.dst); } });
  const showLabel = (n) => n.critical || onPath.has(n.id) || top.has(n.id) || n.id === hover || linked.has(n.id) || n.kind === "AIAgent" || n.kind === "Internet";

  return (
    <svg className={`gmap mode-${mode}`} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
      <defs>
        <marker id="gm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style={{ fill: "var(--line-hover)" }} /></marker>
        <marker id="gm-arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style={{ fill: "var(--red)" }} /></marker>
      </defs>
      {mode === "zones" && Object.entries({ external: "Internet", onprem: "On-premises", cloud: "Cloud" }).map(([z, label]) => (
        <text key={z} className="gm-zone" x={W * ZONE_X[z]} y={22}>{label}</text>
      ))}
      {data.edges.map((e, i) => {
        const a = pos[e.src], b = pos[e.dst];
        if (!a || !b) return null;
        const red = pathEdge.has(`${e.src}>${e.dst}`);
        const dim = (hover && !(e.src === hover || e.dst === hover)) || (path && !red);
        const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, trim = 13;
        return (
          <line key={i} className={`gm-edge ${e.attack ? "attack" : "other"} ${red ? "path" : ""} ${dim ? "dim" : ""}`}
            x1={a.x} y1={a.y} x2={b.x - (dx / len) * trim} y2={b.y - (dy / len) * trim}
            markerEnd={red ? "url(#gm-arrow-red)" : e.attack ? "url(#gm-arrow)" : undefined}>
            <title>{`${e.src} ${e.type} ${e.dst}`}</title>
          </line>
        );
      })}
      {data.nodes.map((n) => {
        const q = pos[n.id];
        const r = radius(n, mode);
        const dim = (hover && !linked.has(n.id) && n.id !== hover) || (path && !onPath.has(n.id));
        return (
          <g key={n.id} className={`gm-node ${dim ? "dim" : ""} ${onPath.has(n.id) ? "on" : ""} loc-${n.location}`}
            onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
            {mode === "choke" && top.has(n.id) && <circle className="gm-ring" cx={q.x} cy={q.y} r={r + 6} />}
            <g style={{ fill: fill(n, mode) }}><Shape kind={n.kind} x={q.x} y={q.y} r={r} className="gm-shape" /></g>
            {showLabel(n) && <text x={q.x} y={q.y - r - 6}>{n.id}</text>}
            <title>{`${n.id} · ${n.kind}${n.community ? ` · community ${n.community}` : ""}${n.pagerank != null ? ` · PageRank ${n.pagerank.toFixed(2)}` : ""}${n.choke != null ? ` · betweenness ${n.choke.toFixed(2)}` : ""}`}</title>
          </g>
        );
      })}
    </svg>
  );
}
