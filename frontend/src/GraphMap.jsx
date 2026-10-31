import { useMemo, useState } from "react";
import { Shape } from "./RingGraph.jsx";

const W = 960;
const H = 600;
// where each location sits across the picture in the zones view: outside on the left, on-premises in the
// middle, cloud on the right, so the left-to-right reading always holds
const ZONE_X = { external: 0.12, onprem: 0.5, cloud: 0.86 };

// node colours from the neo4j browser palette, shared with the nvl view, so the graph reads like neo4j.
// red stays reserved for critical assets.
export const KIND_COLOR = {
  Computer: "#57C7E3", User: "#F79767", Group: "#C990C0", AIAgent: "#8DCC93", Tool: "#FFC454",
  CloudResource: "#4C8EDA", ServiceIdentity: "#569480", Software: "#D9C8AE", Internet: "#ECB5C9",
};

// group names shared with the nvl view, so both renderers caption their clusters the same way
export const GROUP_NAME = {
  critical: "Critical assets", Computer: "Computers", User: "Users", Group: "Groups", AIAgent: "AI agents", Tool: "Agent tools",
  CloudResource: "Cloud resources", ServiceIdentity: "Service identities", Software: "Software", Internet: "Internet",
  onprem: "On-premises", cloud: "Cloud", external: "Internet",
};
export const groupName = (g) => (g === "none" ? "No activity" : GROUP_NAME[g] || (g.startsWith("c") ? `Community ${g.slice(1)}` : g));

// which cluster a node belongs to, per view: communities in the communities view, locations in the location
// view, otherwise node type. critical assets always form their own group so the targets sit together.
export const groupOfNode = (n, mode) =>
  n.critical ? "critical" : mode === "community" ? (n.community ? `c${n.community}` : "none") : mode === "zones" ? (n.location || "onprem") : n.kind;

// attack distance: how many attack steps each node is from the nearest critical asset, worked out backwards from
// the critical assets along the attack steps
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

export const COMMUNITY_COLOR = ["#57C7E3", "#F79767", "#C990C0", "#8DCC93", "#FFC454", "#4C8EDA", "#DA7194", "#569480", "#D9C8AE", "#ECB5C9", "#FFE081", "#A5ABB6"];
export const LOCATION_COLOR = { onprem: "#57C7E3", cloud: "#4C8EDA", external: "#FFC454" };
// the highest-scoring nodes for an algorithm result, critical assets excluded (they are the targets)
export const topBy = (nodes, key, k = 6) => nodes.filter((n) => !n.critical && (n[key] ?? 0) > 0).sort((a, b) => b[key] - a[key]).slice(0, k);

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

// the red the nvl view uses for critical assets, so both renderers paint the targets alike
const CRITICAL = "#F16667";

// what colour a whole cluster wears: its group's colour in the types, communities and zones views, and a quiet
// neutral in the influence and choke views, where only the top-ranked nodes should carry colour
export function groupColor(g, mode) {
  if (g === "critical") return CRITICAL;
  if (mode === "pagerank" || mode === "choke") return null;
  if (mode === "community") return g === "none" ? null : COMMUNITY_COLOR[(parseInt(g.slice(1), 10) - 1) % COMMUNITY_COLOR.length];
  if (mode === "zones") return LOCATION_COLOR[g] || LOCATION_COLOR.onprem;
  return KIND_COLOR[g] || null;
}

// ---- cluster layout -------------------------------------------------------------------------------------
// the same picture nvl draws: each cluster settles as its own island. first the clusters are packed as
// circles sized by membership, then a force layout runs inside and between them: nodes push apart,
// connections pull together, and a strong pull towards the cluster's centre keeps each island whole.
// seeded, so the same graph always lands in the same place.
function makeRand() {
  let seed = 7;
  return () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
}

function packGroups(groups, counts, mode, rand) {
  const r = (g) => 20 + 14 * Math.sqrt(counts[g]);
  const order = [...groups].sort((a, b) => counts[b] - counts[a]);
  const c = {};
  order.forEach((g, i) => {
    if (mode === "zones") { c[g] = { x: W * (ZONE_X[g] ?? 0.5), y: H / 2 + (rand() - 0.5) * 60, r: r(g) }; return; }
    // biggest cluster near the middle, the rest seeded on a loose spiral around it
    const a = i * 2.39996; // golden angle, so clusters never start in a line
    const d = i === 0 ? 0 : 130 + 48 * i;
    c[g] = { x: W / 2 + d * Math.cos(a), y: H / 2 + d * 0.62 * Math.sin(a), r: r(g) };
  });
  // relax: overlapping clusters push apart, everything drifts gently to the middle of the canvas
  for (let it = 0; it < 260; it++) {
    for (let i = 0; i < order.length; i++) {
      for (let j = i + 1; j < order.length; j++) {
        const a = c[order[i]], b = c[order[j]];
        const dx = a.x - b.x, dy = a.y - b.y, d = Math.max(Math.hypot(dx, dy), 0.01);
        // the hull stroke pads each island by ~28px beyond its nodes, so islands need real air between them
        const want = a.r + b.r + 82;
        if (d < want) {
          const push = (want - d) / d * 0.5;
          a.x += dx * push; a.y += dy * push; b.x -= dx * push; b.y -= dy * push;
        }
      }
    }
    for (const g of order) {
      const k = c[g];
      if (mode !== "zones") k.x += (W / 2 - k.x) * 0.02;
      else k.x += (W * (ZONE_X[g] ?? 0.5) - k.x) * 0.3;
      k.y += (H / 2 - k.y) * 0.025;
      k.x = Math.min(W - k.r - 46, Math.max(k.r + 46, k.x));
      k.y = Math.min(H - k.r - 40, Math.max(k.r + 54, k.y));
    }
  }
  return c;
}

function layout(nodes, edges, mode) {
  const rand = makeRand();
  const groupOf = Object.fromEntries(nodes.map((n) => [n.id, groupOfNode(n, mode)]));
  const counts = {};
  nodes.forEach((n) => (counts[groupOf[n.id]] = (counts[groupOf[n.id]] || 0) + 1));
  const centres = packGroups(Object.keys(counts), counts, mode, rand);

  const p = nodes.map((n) => {
    const c = centres[groupOf[n.id]];
    const a = rand() * 2 * Math.PI, d = rand() * c.r * 0.6;
    return { id: n.id, g: groupOf[n.id], x: c.x + d * Math.cos(a), y: c.y + d * Math.sin(a) };
  });
  const at = Object.fromEntries(p.map((q, i) => [q.id, i]));
  const links = edges.map((e) => [at[e.src], at[e.dst]]).filter(([a, b]) => a != null && b != null && a !== b);

  const steps = 320;
  const k = 30;
  for (let it = 0; it < steps; it++) {
    const temp = 24 * (1 - it / steps) + 0.4;
    const dx = new Float64Array(p.length), dy = new Float64Array(p.length);
    for (let i = 0; i < p.length; i++) {
      for (let j = i + 1; j < p.length; j++) {
        const ex = p[i].x - p[j].x, ey = p[i].y - p[j].y;
        const d = Math.max(Math.hypot(ex, ey), 0.01);
        if (d > 160) continue; // far nodes no longer push: keeps islands from inflating
        const f = (k * k) / d / d;
        dx[i] += ex * f; dy[i] += ey * f; dx[j] -= ex * f; dy[j] -= ey * f;
      }
    }
    for (const [a, b] of links) {
      // connections tug within a cluster; across clusters barely, so the islands stay apart
      const w = p[a].g === p[b].g ? 0.045 : 0.004;
      const ex = p[a].x - p[b].x, ey = p[a].y - p[b].y;
      const d = Math.max(Math.hypot(ex, ey), 0.01);
      const f = (d * d) / k * w / d;
      dx[a] -= ex * f; dy[a] -= ey * f; dx[b] += ex * f; dy[b] += ey * f;
    }
    for (let i = 0; i < p.length; i++) {
      const c = centres[p[i].g];
      dx[i] += (c.x - p[i].x) * 0.06;
      dy[i] += (c.y - p[i].y) * 0.06;
      // a node that strays outside its cluster's circle is pulled firmly back in
      const ox = p[i].x - c.x, oy = p[i].y - c.y, od = Math.hypot(ox, oy);
      if (od > c.r - 12) { dx[i] -= ox / od * (od - (c.r - 12)) * 0.6; dy[i] -= oy / od * (od - (c.r - 12)) * 0.6; }
      const d = Math.max(Math.hypot(dx[i], dy[i]), 0.01), step = Math.min(d, temp);
      p[i].x = Math.min(W - 44, Math.max(44, p[i].x + (dx[i] / d) * step));
      p[i].y = Math.min(H - 44, Math.max(52, p[i].y + (dy[i] / d) * step));
    }
  }
  return Object.fromEntries(p.map((q) => [q.id, q]));
}

// ---- hulls ----------------------------------------------------------------------------------------------
// convex hull of each cluster's node centres (andrew's monotone chain). the hull is drawn with a very wide
// round-joined stroke, which pads and rounds it in one go - no offset geometry needed.
function hull(points) {
  const pts = [...points].sort((a, b) => a.x - b.x || a.y - b.y);
  if (pts.length < 3) return pts;
  const cross = (o, a, b) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const half = (list) => {
    const out = [];
    for (const q of list) {
      while (out.length > 1 && cross(out[out.length - 2], out[out.length - 1], q) <= 0) out.pop();
      out.push(q);
    }
    return out;
  };
  const lower = half(pts), upper = half([...pts].reverse());
  return [...lower.slice(0, -1), ...upper.slice(0, -1)];
}
// a lone node still gets an island: a zero-length path draws nothing, so give it a hair of length for the
// round caps to wrap around
const hullPath = (pts) =>
  pts.length === 1 ? `M${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}l0.01 0`
  : pts.length ? pts.map((q, i) => `${i ? "L" : "M"}${q.x.toFixed(1)} ${q.y.toFixed(1)}`).join("") + "Z" : "";

function radius(n, mode) {
  if (mode === "pagerank") return 6 + 14 * (n.pagerank ?? 0);
  if (mode === "choke") return 6 + 14 * (n.choke ?? 0);
  return n.critical ? 11 : 8;
}

// labels try above, then below, right and left of their node, and take the first spot that covers neither a
// node nor a label already placed, so names in a dense cluster stop landing on each other
function placeLabels(labelled, nodes, pos, rOf, reserved = []) {
  const boxes = [...reserved, ...nodes.filter((n) => pos[n.id]).map((n) => {
    const q = pos[n.id], r = rOf[n.id];
    return [q.x - r, q.y - r, q.x + r, q.y + r];
  })];
  const ov = (a, b) => Math.max(0, Math.min(a[2], b[2]) - Math.max(a[0], b[0])) * Math.max(0, Math.min(a[3], b[3]) - Math.max(a[1], b[1]));
  const out = {};
  for (const n of labelled) {
    const q = pos[n.id], r = rOf[n.id], w = n.id.length * 7, h = 13;
    const cands = [
      { x: q.x, y: q.y - r - 7, anchor: "middle", box: [q.x - w / 2, q.y - r - 7 - h, q.x + w / 2, q.y - r - 7] },
      { x: q.x, y: q.y + r + 14, anchor: "middle", box: [q.x - w / 2, q.y + r + 3, q.x + w / 2, q.y + r + 16] },
      { x: q.x + r + 6, y: q.y + 4, anchor: "start", box: [q.x + r + 6, q.y - 7, q.x + r + 6 + w, q.y + 6] },
      { x: q.x - r - 6, y: q.y + 4, anchor: "end", box: [q.x - r - 6 - w, q.y - 7, q.x - r - 6, q.y + 6] },
    ];
    const cost = (c) => boxes.reduce((s, t) => s + ov(c.box, t), 0);
    const best = cands.find((c) => cost(c) === 0) || cands.reduce((x, c) => (cost(c) < cost(x) ? c : x));
    out[n.id] = best;
    boxes.push(best.box);
  }
  return out;
}

// node colour, with the nvl view's reading: in the influence and choke views everything but the top-ranked
// nodes goes quiet, so the answer stands out instead of a gradient nobody can read
function fill(n, mode, top) {
  if (mode === "pagerank" || mode === "choke") {
    if (!top.has(n.id)) return n.critical ? "color-mix(in srgb, var(--red) 45%, var(--surface))" : "var(--node)";
    return mode === "choke" ? "var(--amber)" : (n.critical ? CRITICAL : KIND_COLOR[n.kind] || "var(--node)");
  }
  if (n.critical) return CRITICAL;
  if (mode === "community") return n.community ? COMMUNITY_COLOR[(n.community - 1) % COMMUNITY_COLOR.length] : "var(--node)";
  if (mode === "zones") return LOCATION_COLOR[n.location] || LOCATION_COLOR.onprem;
  return KIND_COLOR[n.kind] || "var(--node)";
}

// the whole graph, drawn once. mode switches what the clusters, colour and size mean; path draws one route
// in red on top.
export default function GraphMap({ data, mode, path }) {
  const [hover, setHover] = useState(null);
  const pos = useMemo(() => layout(data.nodes, data.edges, mode), [data, mode]);
  const onPath = new Set(path?.ids || []);
  const pathEdge = new Set((path?.ids || []).slice(1).map((id, i) => `${path.ids[i]}>${id}`));
  const top = useMemo(() => new Set(
    (mode === "pagerank" || mode === "choke") ? topBy(data.nodes, mode === "choke" ? "choke" : "pagerank").map((n) => n.id) : []
  ), [data, mode]);
  const linked = new Set();
  if (hover) data.edges.forEach((e) => { if (e.src === hover || e.dst === hover) { linked.add(e.src); linked.add(e.dst); } });
  const showLabel = (n) => n.critical || onPath.has(n.id) || top.has(n.id) || n.id === hover || linked.has(n.id) || n.kind === "AIAgent" || n.kind === "Internet";
  const rOf = Object.fromEntries(data.nodes.map((n) => [n.id, radius(n, mode)]));

  // one hull per cluster, plus its caption pill above it
  const hulls = useMemo(() => {
    const byGroup = {};
    data.nodes.forEach((n) => { const q = pos[n.id]; if (q) (byGroup[q.g] ||= []).push(q); });
    return Object.entries(byGroup).map(([g, pts]) => {
      const h = hull(pts);
      const top_ = Math.min(...pts.map((q) => q.y));
      const cx = pts.reduce((s, q) => s + q.x, 0) / pts.length;
      return { g, d: hullPath(h), count: pts.length, cx, cy: top_ };
    });
  }, [data, pos]);

  // caption pill geometry up front, so node labels can keep out of the pills' way
  const pills = hulls.filter((h) => h.count > 1).map(({ g, count, cx, cy }) => {
    const name = `${groupName(g)} · ${count}`;
    const pw = name.length * 6.6 + 20;
    const px = Math.min(W - pw / 2 - 6, Math.max(pw / 2 + 6, cx));
    const py = Math.max(16, cy - 48);
    return { g, name, pw, px, py, box: [px - pw / 2, py - 14, px + pw / 2, py + 7] };
  });
  const labels = placeLabels(data.nodes.filter(showLabel), data.nodes, pos, rOf, pills.map((p) => p.box));

  return (
    <svg className={`gmap mode-${mode}`} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
      <defs>
        <marker id="gm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style={{ fill: "var(--line-hover)" }} /></marker>
        <marker id="gm-arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style={{ fill: "var(--red)" }} /></marker>
        <filter id="gm-glow" x="-80%" y="-80%" width="260%" height="260%"><feGaussianBlur stdDeviation="5" /></filter>
      </defs>

      {hulls.map(({ g, d }) => {
        const color = groupColor(g, mode);
        return (
          <g key={g} className="gm-cluster">
            {/* three strokes of the same hull: a wide soft halo, a rim in the cluster's colour, and a body
                that fills the island with a faint tint of it */}
            <path d={d} className="gm-hull-halo" style={{ stroke: color || "var(--line)", fill: color || "var(--line)" }} />
            <path d={d} className="gm-hull-rim" style={{ stroke: color || "var(--line-hover)", fill: "none" }} />
            <path d={d} className="gm-hull-body" style={{
              stroke: `color-mix(in srgb, var(--surface) 88%, ${color || "var(--line-hover)"})`,
              fill: `color-mix(in srgb, var(--surface) 88%, ${color || "var(--line-hover)"})`,
            }} />
          </g>
        );
      })}

      {data.edges.map((e, i) => {
        const a = pos[e.src], b = pos[e.dst];
        if (!a || !b) return null;
        const red = pathEdge.has(`${e.src}>${e.dst}`);
        const dim = (hover && !(e.src === hover || e.dst === hover)) || (path && !red);
        const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, trim = (rOf[e.dst] || 8) + 5;
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
        const r = rOf[n.id];
        const dim = (hover && !linked.has(n.id) && n.id !== hover) || (path && !onPath.has(n.id));
        const c = fill(n, mode, top);
        const lit = n.critical || top.has(n.id) || n.id === hover;
        const lab = labels[n.id];
        return (
          <g key={n.id} className={`gm-node ${dim ? "dim" : ""} ${onPath.has(n.id) ? "on" : ""} loc-${n.location}`}
            onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
            {lit && !dim && <circle className="gm-glow" cx={q.x} cy={q.y} r={r * 1.9} style={{ fill: c }} filter="url(#gm-glow)" />}
            {top.has(n.id) && <circle className={`gm-ring ${mode}`} cx={q.x} cy={q.y} r={r + 6} />}
            <g style={{ fill: c }}><Shape kind={n.kind} x={q.x} y={q.y} r={r} className="gm-shape" /></g>
            {lab && <text x={lab.x} y={lab.y} style={{ textAnchor: lab.anchor }}>{n.id}</text>}
            <title>{`${n.id} · ${n.kind}${n.community ? ` · community ${n.community}` : ""}${n.pagerank != null ? ` · PageRank ${n.pagerank.toFixed(2)}` : ""}${n.choke != null ? ` · betweenness ${n.choke.toFixed(2)}` : ""}`}</title>
          </g>
        );
      })}

      {/* cluster captions last, so no island or node ever covers them */}
      {pills.map(({ g, name, pw, px, py }) => {
        const color = groupColor(g, mode);
        return (
          <g key={g} className={`gm-pill ${g === "critical" ? "crit" : ""}`}>
            <rect x={px - pw / 2} y={py - 14} width={pw} height={21} rx={10.5} />
            {color && <circle cx={px - pw / 2 + 11} cy={py - 3.5} r={3.2} style={{ fill: color }} />}
            <text x={px + (color ? 6 : 0)} y={py + 1}>{name}</text>
          </g>
        );
      })}
    </svg>
  );
}
