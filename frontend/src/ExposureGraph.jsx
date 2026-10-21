import { useMemo } from "react";

const KIND_SHAPE = { User: "circle", Group: "square", Computer: "diamond" };
const PAD_X = 70;
const PAD_Y = 34;
const ROW = 46;

// a left-to-right attack graph: sources in the first column, critical assets in the last, every node placed in
// the column of its fewest steps from a source. this is the kill chain the paths share, read left to right.
export default function ExposureGraph({ data, chokeIds, removedNodes, removedEdges, remaining, onPickEdge, pickedEdge }) {
  const { nodes, edges } = data;
  const layout = useMemo(() => {
    const maxLayer = Math.max(0, ...nodes.map((n) => n.layer));
    const cols = Array.from({ length: maxLayer + 1 }, () => []);
    [...nodes].sort((a, b) => a.id.localeCompare(b.id)).forEach((n) => cols[n.layer].push(n));
    const height = Math.max(...cols.map((c) => c.length), 1) * ROW + PAD_Y * 2;
    const colW = 210;
    const width = PAD_X * 2 + maxLayer * colW;
    const pos = {};
    cols.forEach((col, layer) => {
      const top = (height - col.length * ROW) / 2 + ROW / 2;
      col.forEach((n, i) => { pos[n.id] = { x: PAD_X + layer * colW, y: top + i * ROW }; });
    });
    return { pos, width, height, maxLayer };
  }, [nodes]);

  const removedEdgeSet = new Set((removedEdges || []).map((e) => `${e.src}>${e.dst}`));
  const removedNodeSet = new Set(removedNodes || []);
  const choke = new Set(chokeIds || []);

  return (
    <svg className="exp-graph" viewBox={`0 0 ${layout.width} ${layout.height}`} preserveAspectRatio="xMinYMid meet">
      <defs>
        <marker id="exp-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M0 0L10 5L0 10z" style={{ fill: "var(--line-hover)" }} />
        </marker>
      </defs>
      {edges.map((e, i) => {
        const a = layout.pos[e.src], b = layout.pos[e.dst];
        if (!a || !b) return null;
        const key = `${e.src}>${e.dst}`;
        const cut = removedEdgeSet.has(key) || removedNodeSet.has(e.src) || removedNodeSet.has(e.dst);
        const kept = remaining && !cut && remaining.edges.has(key);
        const faded = remaining && !cut && !kept;
        const picked = pickedEdge === key;
        const midx = (a.x + b.x) / 2, midy = (a.y + b.y) / 2;
        const label = e.technique || e.type;
        return (
          <g key={i} className={`exp-edge ${cut ? "cut" : ""} ${kept ? "kept" : ""} ${faded ? "faded" : ""} ${picked ? "picked" : ""}`} onClick={() => onPickEdge?.(e)}>
            <path d={`M${a.x + 10} ${a.y} C ${midx} ${a.y}, ${midx} ${b.y}, ${b.x - 14} ${b.y}`} markerEnd="url(#exp-arrow)" />
            <text x={midx} y={midy - 5}>{label}</text>
          </g>
        );
      })}
      {nodes.map((n) => {
        const p = layout.pos[n.id];
        if (!p) return null;
        const cut = removedNodeSet.has(n.id);
        const faded = remaining && !cut && !remaining.nodes.has(n.id) && !n.critical && !n.source;
        const cls = n.critical ? "target" : n.source ? "source" : choke.has(n.id) ? "choke" : "mid";
        return (
          <g key={n.id} className={`exp-node ${cls} ${cut ? "cut" : ""} ${faded ? "faded" : ""}`}>
            <Shape kind={n.kind} x={p.x} y={p.y} r={n.critical || n.source ? 10 : 8} />
            {choke.has(n.id) && !n.critical && !n.source && <circle className="choke-ring" cx={p.x} cy={p.y} r={16} />}
            <text x={p.x} y={p.y - 15}>{n.id}</text>
          </g>
        );
      })}
    </svg>
  );
}

function Shape({ kind, x, y, r }) {
  const shape = KIND_SHAPE[kind] || "circle";
  if (shape === "square") return <rect className="shape" x={x - r} y={y - r} width={2 * r} height={2 * r} rx={r * 0.35} />;
  if (shape === "diamond") return <rect className="shape" x={x - r * 0.85} y={y - r * 0.85} width={1.7 * r} height={1.7 * r} rx={r * 0.25} transform={`rotate(45 ${x} ${y})`} />;
  return <circle className="shape" cx={x} cy={y} r={r} />;
}
