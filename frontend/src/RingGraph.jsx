import { useMemo, useState } from "react";
import { shortId } from "./parts.jsx";

const W = 780;
const H = 660;
const CX = W / 2;
const CY = H / 2;
const RADII = [0, 120, 215, 300];
// more rings for the explore view, which follows paths further than the 3-hop blast radius
const RADII_WIDE = [0, 90, 160, 225, 285, 340, 390, 435, 475];
const radiiFor = (maxHop) => (maxHop <= 3 ? RADII : RADII_WIDE);
const KIND_SHAPE = {
  User: "circle", Group: "square", Computer: "diamond", AIAgent: "hexagon", CloudResource: "cloud",
  ServiceIdentity: "ring", Tool: "triangle", Internet: "globe",
};

// place nodes on rings by hop. each ring is ordered by the angle of the node that leads to it,
// so lines stay short and do not cross the whole picture.
function layout(nodes, edges, radii = RADII) {
  const byHop = radii.map((_, h) => nodes.filter((n) => n.hop === h));
  const pos = {};
  const centre = byHop[0];
  centre.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(centre.length, 1) - Math.PI / 2;
    const r = centre.length > 1 ? 34 : 0;
    pos[n.id] = { x: CX + r * Math.cos(a), y: CY + r * Math.sin(a), a };
  });
  const neighbours = {};
  edges.forEach((e) => {
    (neighbours[e.src] ||= []).push(e.dst);
    (neighbours[e.dst] ||= []).push(e.src);
  });
  for (let h = 1; h < radii.length; h++) {
    const ring = byHop[h];
    if (!ring.length) continue;
    const wanted = ring.map((n) => {
      const parents = (neighbours[n.id] || []).filter((id) => pos[id] && nodes.find((x) => x.id === id)?.hop === h - 1);
      const angles = parents.map((id) => pos[id].a);
      const a = angles.length
        ? Math.atan2(angles.reduce((s, x) => s + Math.sin(x), 0), angles.reduce((s, x) => s + Math.cos(x), 0))
        : 0;
      return { n, a };
    });
    wanted.sort((p, q) => p.a - q.a);
    const step = (2 * Math.PI) / ring.length;
    // if a node would sit at the same angle as one on an inner ring, they line up and their labels collide:
    // rotate this ring by half a step in that case
    const inner = Object.values(pos).filter((q) => q.h > 0).map((q) => q.a);
    const gap = (off) => Math.min(Infinity, ...wanted.flatMap((_, i) => inner.map((b) =>
      Math.abs(((off + step * i - b) % (2 * Math.PI) + 3 * Math.PI) % (2 * Math.PI) - Math.PI))));
    // try the natural angle, then half a step, then small nudges either way, until nothing lines up;
    // if every try lines up with something, take the one that keeps the most room
    const base = wanted[0].a;
    const tries = [0, step / 2, 0.35, -0.35, 0.7, -0.7, 1.05, -1.05, step / 4, -step / 4].map((d) => base + d);
    const offset = tries.find((t) => gap(t) >= 0.2) ?? tries.reduce((x, t) => (gap(t) > gap(x) ? t : x));
    wanted.forEach(({ n }, i) => {
      const a = offset + step * i;
      pos[n.id] = { x: CX + radii[h] * Math.cos(a), y: CY + radii[h] * Math.sin(a), a, h };
    });
  }
  return pos;
}

export function Shape({ kind, x, y, r, className }) {
  const shape = KIND_SHAPE[kind] || "circle";
  if (shape === "square") return <rect className={className} x={x - r} y={y - r} width={2 * r} height={2 * r} rx={r * 0.35} />;
  if (shape === "diamond") return <rect className={className} x={x - r * 0.85} y={y - r * 0.85} width={1.7 * r} height={1.7 * r} rx={r * 0.25} transform={`rotate(45 ${x} ${y})`} />;
  if (shape === "hexagon") {
    const pts = [0, 1, 2, 3, 4, 5].map((i) => { const a = Math.PI / 6 + (i * Math.PI) / 3; return `${x + r * 1.1 * Math.cos(a)},${y + r * 1.1 * Math.sin(a)}`; });
    return <polygon className={className} points={pts.join(" ")} />;
  }
  if (shape === "triangle") return <polygon className={className} points={`${x},${y - r * 1.15} ${x + r * 1.05},${y + r * 0.8} ${x - r * 1.05},${y + r * 0.8}`} />;
  if (shape === "cloud") return <rect className={className} x={x - r * 1.35} y={y - r * 0.8} width={2.7 * r} height={1.6 * r} rx={r * 0.8} />;
  if (shape === "ring") return <circle className={`${className} ring-shape`} cx={x} cy={y} r={r * 0.95} />;
  if (shape === "globe") return <g className={className}><circle cx={x} cy={y} r={r * 1.1} /><ellipse cx={x} cy={y} rx={r * 0.45} ry={r * 1.1} className="globe-line" /><line x1={x - r * 1.1} y1={y} x2={x + r * 1.1} y2={y} className="globe-line" /></g>;
  return <circle className={className} cx={x} cy={y} r={r} />;
}

// labels sit outward from the centre: to the side for nodes left and right of it, below or above otherwise.
// if that spot would cover another node or a label already placed, the first free side is used instead.
const CHAR_W = 8.2;
const nodeSize = (n) => (n.critical || n.hop === 0 ? 17 : 13);
function candidates(p, r, w, k) {
  const dx = p.x - CX, dy = p.y - CY, d = Math.hypot(dx, dy);
  const g = 8 * k, h = 16 * k;
  const right = { x: p.x + r + g, y: p.y + 5 * k, anchor: "start", box: [p.x + r + g, p.y - h / 2 - 2, p.x + r + g + w, p.y + h / 2 - 2] };
  const left = { x: p.x - r - g, y: p.y + 5 * k, anchor: "end", box: [p.x - r - g - w, p.y - h / 2 - 2, p.x - r - g, p.y + h / 2 - 2] };
  const below = { x: p.x, y: p.y + r + 4 + h, anchor: "middle", box: [p.x - w / 2, p.y + r + 4, p.x + w / 2, p.y + r + 4 + h] };
  const above = { x: p.x, y: p.y - r - 8, anchor: "middle", box: [p.x - w / 2, p.y - r - 6 - h, p.x + w / 2, p.y - r - 6] };
  if (d < 1 || Math.abs(dx) / d < 0.45) return d < 1 || dy >= 0 ? [below, above, right, left] : [above, below, right, left];
  return dx > 0 ? [right, below, above, left] : [left, below, above, right];
}
const overlap = (a, b) => Math.max(0, Math.min(a[2], b[2]) - Math.max(a[0], b[0])) * Math.max(0, Math.min(a[3], b[3]) - Math.max(a[1], b[1]));
function placeLabels(nodes, pos, k) {
  const placed = {};
  const taken = nodes.filter((n) => pos[n.id]).map((n) => {
    const p = pos[n.id], r = nodeSize(n);
    return { id: n.id, box: [p.x - r, p.y - r, p.x + r, p.y + r] };
  });
  [...nodes].sort((a, b) => a.hop - b.hop).forEach((n) => {
    const p = pos[n.id];
    if (!p) return;
    const opts = candidates(p, nodeSize(n), n.id.length * CHAR_W * k, k);
    const cost = (o) => taken.reduce((s, t) => s + (t.id === n.id ? 0 : overlap(o.box, t.box)), 0);
    const best = opts.find((o) => cost(o) === 0) || opts.reduce((x, o) => (cost(o) < cost(x) ? o : x));
    placed[n.id] = best;
    taken.push({ id: `label:${n.id}`, box: best.box });
  });
  return placed;
}

export default function RingGraph({ data: full, onSelectNode, selectedNode, maxHop = 3, highlight = null }) {
  const [hover, setHover] = useState(null);
  // positions come from the full graph so nodes do not jump when the hop filter changes
  const radii = radiiFor(maxHop);
  const pos = useMemo(() => (full ? layout(full.nodes, full.edges, radii) : {}), [full, radii]);
  const data = useMemo(() => {
    if (!full) return null;
    const keep = new Set(full.nodes.filter((n) => n.hop <= maxHop).map((n) => n.id));
    return { ...full, nodes: full.nodes.filter((n) => keep.has(n.id)), edges: full.edges.filter((e) => keep.has(e.src) && keep.has(e.dst)) };
  }, [full, maxHop]);
  // fit the picture to the rings actually drawn, so a small blast radius is drawn large and readable;
  // labels grow with the picture so they read the same size on screen
  const outer = data ? Math.max(1, ...data.nodes.map((n) => n.hop)) : 1;
  const extent = Math.max(230, radii[Math.min(outer, maxHop, radii.length - 1)] + 60);
  const k = Math.max(1, extent / 400);
  const labels = useMemo(() => (data ? placeLabels(data.nodes, pos, k) : {}), [data, pos, k]);
  if (!data) return null;
  const viewBox = `${CX - extent} ${CY - extent} ${2 * extent} ${2 * extent}`;

  // highlight: a list of paths (each a list of node ids) to draw in red; otherwise the alert's attack path
  const paths = highlight ?? (data.attack_path?.nodes ? [data.attack_path.nodes] : []);
  const pathIds = [...new Set(paths.flat())];
  const pathEdge = new Set(paths.flatMap((p) => p.slice(1).map((id, i) => `${p[i]}>${id}`)));
  const focus = hover || selectedNode;
  const linked = new Set();
  if (focus) data.edges.forEach((e) => { if (e.src === focus || e.dst === focus) { linked.add(e.src); linked.add(e.dst); } });

  return (
    <svg className="ring-graph" viewBox={viewBox} preserveAspectRatio="xMidYMid meet" key={data.alert_id}>
      <defs>
        <radialGradient id="halo-red"><stop offset="0" style={{ stopColor: "var(--red)", stopOpacity: 0.28 }} /><stop offset="1" style={{ stopColor: "var(--red)", stopOpacity: 0 }} /></radialGradient>
        <radialGradient id="halo-amber"><stop offset="0" style={{ stopColor: "var(--amber)", stopOpacity: 0.22 }} /><stop offset="1" style={{ stopColor: "var(--amber)", stopOpacity: 0 }} /></radialGradient>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style={{ fill: "var(--line-hover)" }} /></marker>
        <marker id="arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" style={{ fill: "var(--red)" }} /></marker>
      </defs>

      {radii.slice(1, maxHop + 1).map((r, i) => (
        <g key={r} className="ring" style={{ animationDelay: `${i * 0.18}s` }}>
          <circle cx={CX} cy={CY} r={r} />
        </g>
      ))}

      {data.edges.map((e, i) => {
        const a = pos[e.src], b = pos[e.dst];
        if (!a || !b) return null;
        const onPath = pathEdge.has(`${e.src}>${e.dst}`);
        const dim = focus && !(e.src === focus || e.dst === focus);
        const lit = focus && !dim;
        const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
        const trim = 19;
        const x2 = b.x - (dx / len) * trim, y2 = b.y - (dy / len) * trim;
        return (
          <g key={i} className={`edge ${onPath ? "path" : ""} ${e.secured ? "secured" : ""} ${dim ? "dim" : ""} ${lit ? "lit" : ""}`}>
            <line x1={a.x} y1={a.y} x2={x2} y2={y2} markerEnd={onPath ? "url(#arrow-red)" : "url(#arrow)"} />
            {lit && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4}>{e.type}</text>}
          </g>
        );
      })}

      {data.nodes.map((n) => {
        const p = pos[n.id];
        if (!p) return null;
        const onPath = pathIds.includes(n.id);
        const dim = focus && !linked.has(n.id) && n.id !== focus;
        const cls = n.hop === 0 ? "alerted" : n.critical ? "critical" : onPath ? "onpath" : `hop${n.hop}`;
        const r = nodeSize(n);
        return (
          <g
            key={n.id}
            className={`node ${cls} loc-${n.location || "onprem"} ${dim ? "dim" : ""} ${selectedNode === n.id ? "selected" : ""}`}
            style={{ animationDelay: `${0.15 + n.hop * 0.18}s` }}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover(null)}
            onClick={() => onSelectNode(n.id === selectedNode ? null : n.id)}
          >
            {(n.critical || n.hop === 0) && <circle cx={p.x} cy={p.y} r={r * 2.6} fill={n.critical ? "url(#halo-red)" : "url(#halo-amber)"} />}
            <Shape kind={n.kind} x={p.x} y={p.y} r={r} className="shape" />
            {labels[n.id] && <text x={labels[n.id].x} y={labels[n.id].y} style={{ textAnchor: labels[n.id].anchor, fontSize: 15 * k }}>{shortId(n.id)}</text>}
            {n.kev && <g className="kev-badge"><title>Runs software with a known-exploited vulnerability</title><circle cx={p.x + r} cy={p.y - r} r={7} /><text x={p.x + r} y={p.y - r + 4}>!</text></g>}
          </g>
        );
      })}
    </svg>
  );
}
