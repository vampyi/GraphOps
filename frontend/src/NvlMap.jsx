import { useEffect, useMemo, useRef, useState } from "react";
import { InteractiveNvlWrapper } from "@neo4j-nvl/react";
import { COLUMNS, distances, KIND_COLOR } from "./GraphMap.jsx";


const LOC_ORDER = { external: 0, onprem: 1, cloud: 2 };
const KIND_ORDER = ["Internet", "Computer", "User", "Group", "AIAgent", "Tool", "ServiceIdentity", "CloudResource", "Software"];

const column = (d) => (d == null ? "none" : d >= 4 ? 4 : d);
const COL_W = 400;
const ROW_H = 150;

function positions(data, dist) {
  const cols = Object.fromEntries(COLUMNS.map((c) => [c.key, []]));
  data.nodes.forEach((n) => cols[column(dist[n.id])].push(n));
  const out = [];
  COLUMNS.forEach((c, ci) => {
    const list = cols[c.key].sort((a, b) => (LOC_ORDER[a.location] ?? 1) - (LOC_ORDER[b.location] ?? 1)
      || KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || a.id.localeCompare(b.id));
    // tall columns wrap into two staggered lanes so they stay readable
    const lanes = list.length > 9 ? 2 : 1;
    const rows = Math.ceil(list.length / lanes);
    list.forEach((n, i) => {
      const lane = i % lanes, row = Math.floor(i / lanes);
      out.push({ id: n.id, x: ci * COL_W + (lanes > 1 ? (lane - 0.5) * 165 : 0), y: (row - (rows - 1) / 2) * ROW_H + (lane ? ROW_H / 2 : 0) });
    });
    out.push({ id: `__col${ci}`, x: ci * COL_W, y: -((Math.max(...COLUMNS.map((k) => Math.ceil(cols[k.key].length / (cols[k.key].length > 9 ? 2 : 1)))) - 1) / 2) * ROW_H - 150 });
  });
  return out;
}

const CRITICAL = "#F16667";
const COMMUNITY = ["#57C7E3", "#F79767", "#C990C0", "#8DCC93", "#FFC454", "#4C8EDA", "#DA7194", "#569480", "#D9C8AE", "#ECB5C9", "#FFE081", "#A5ABB6"];
const LOCATION = { onprem: "#57C7E3", cloud: "#4C8EDA", external: "#FFC454" };

// mix two hex colours: 0 gives a, 1 gives b. used to shade nodes by an algorithm score.
function ramp(a, b, t) {
  const x = (h, i) => parseInt(h.slice(1 + 2 * i, 3 + 2 * i), 16);
  const k = Math.max(0, Math.min(1, t));
  return "#" + [0, 1, 2].map((i) => Math.round(x(a, i) + (x(b, i) - x(a, i)) * k).toString(16).padStart(2, "0")).join("");
}

function color(n, mode) {
  if (n.critical) return CRITICAL;
  if (mode === "community") return n.community ? COMMUNITY[(n.community - 1) % COMMUNITY.length] : "#A5ABB6";
  if (mode === "zones") return LOCATION[n.location] || LOCATION.onprem;
  if (mode === "choke") return ramp("#A5ABB6", "#FFB020", n.choke ?? 0);
  if (mode === "pagerank") return ramp("#A5ABB6", "#2BB3D8", n.pagerank ?? 0);
  return KIND_COLOR[n.kind] || "#A5ABB6";
}

function size(n, mode) {
  if (mode === "pagerank") return 56 + 34 * (n.pagerank ?? 0);
  if (mode === "choke") return 56 + 34 * (n.choke ?? 0);
  return n.critical ? 80 : 70;
}

// the whole graph drawn with neo4j's own visualization library (nvl). drag, zoom and pan; click a node for its
// algorithm scores. nvl is licensed for use with neo4j aura, so the graph tab only uses it when the backend
// reports an aura database.
export default function NvlMap({ data, mode, path, dark }) {
  const nvl = useRef(null);
  const dist = useMemo(() => distances(data), [data]);
  const pos = useMemo(() => positions(data, dist), [data, dist]);
  const bg = dark ? "#111018" : "#ffffff";
  const [picked, setPicked] = useState(null);
  const onPath = useMemo(() => new Set(path?.ids || []), [path]);
  const pathRel = useMemo(() => new Set((path?.ids || []).slice(1).map((id, i) => `${path.ids[i]}>${id}`)), [path]);

  // each column heading has an invisible anchor node; the heading text is a page label kept over its anchor
  const heads = useMemo(() => COLUMNS.map((c, ci) => ({ id: `__col${ci}`, color: bg, size: 1 })), [bg]);
  const [headPos, setHeadPos] = useState([]);
  useEffect(() => {
    let raf, last = "";
    const tick = () => {
      const ns = nvl.current?.getNodes?.() || [];
      const hs = ns.filter((n) => n.id.startsWith("__col")).map((n) => ({ i: +n.id.slice(5), x: n.clientPosition.x, y: n.clientPosition.y }));
      const key = hs.map((h) => `${h.i}:${Math.round(h.x)}:${Math.round(h.y)}`).join("|");
      if (key !== last) { last = key; setHeadPos(hs); }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const nodes = useMemo(() => [...heads, ...data.nodes.map((n) => ({
    id: n.id, caption: n.id, color: color(n, mode), size: size(n, mode),
    selected: onPath.has(n.id) || picked === n.id, disabled: !!path && !onPath.has(n.id),
  }))], [heads, data, mode, path, onPath, picked]);
  // only attack steps are drawn, so the hierarchical layout can read them as a left-to-right flow towards the
  // critical assets. logins and network connections stay in the explore and triage views.
  const rels = useMemo(() => data.edges.filter((e) => e.attack).map((e, i) => {
    const red = pathRel.has(`${e.src}>${e.dst}`);
    return {
      id: `r${i}`, from: e.src, to: e.dst, caption: e.type,
      color: red ? CRITICAL : e.attack ? (dark ? "#8C8FA3" : "#7B7F8F") : (dark ? "#4A4D5C" : "#C4C7D0"),
      width: red ? 4 : e.attack ? 1.5 : 1, disabled: !!path && !red,
    };
  }), [data, path, pathRel, dark]);

  const fit = () => nvl.current?.fit(pos.map((p) => p.id));
  const zoomBy = (f) => nvl.current && nvl.current.setZoom(nvl.current.getScale() * f);

  // zoom to fit once the force layout has had time to settle, and again when the graph changes
  useEffect(() => {
    const t = setTimeout(() => fit(), 600);
    return () => clearTimeout(t);
  }, [data]);

  const node = picked && data.nodes.find((n) => n.id === picked);
  return (
    <div className="nvl-wrap">
      <InteractiveNvlWrapper
        ref={nvl}
        positions={pos}
        nodes={nodes}
        rels={rels}
        nvlOptions={{ layout: "free", renderer: "canvas", disableTelemetry: true, minZoom: 0.05, maxZoom: 4, allowDynamicMinZoom: true,
          styling: { selectedBorderColor: CRITICAL, disabledItemColor: dark ? "#2A2C36" : "#E4E5EA", disabledItemFontColor: dark ? "#55586A" : "#A8ABB6" } }}
        nvlCallbacks={{ onLayoutDone: () => nvl.current?.fit(data.nodes.map((n) => n.id)) }}
        mouseEventCallbacks={{
          onZoom: true, onPan: true, onDrag: true, onHover: true,
          onNodeClick: (n) => !n.id.startsWith("__col") && setPicked(n.id === picked ? null : n.id),
          onCanvasClick: () => setPicked(null),
        }}
      />
      {headPos.map((h) => (
        <div key={h.i} className={`nvl-col ${COLUMNS[h.i].key === 0 ? "crit" : ""}`} style={{ left: h.x, top: h.y }}>{COLUMNS[h.i].label}</div>
      ))}
      <div className="nvl-zoom">
        <button onClick={() => zoomBy(1.3)} aria-label="Zoom in" title="Zoom in">+</button>
        <button onClick={() => zoomBy(1 / 1.3)} aria-label="Zoom out" title="Zoom out">−</button>
        <button onClick={fit} aria-label="Fit to screen" title="Fit to screen">⤢</button>
      </div>
      {node && (
        <div className="nvl-card">
          <button className="x" onClick={() => setPicked(null)} aria-label="Close">×</button>
          <div className="nvl-card-kind"><i style={{ background: KIND_COLOR[node.kind] }} />{node.kind}{node.critical ? " · critical" : ""}</div>
          <div className="nvl-card-id">{node.id}</div>
          <dl>
            <dt>Location</dt><dd>{node.location}</dd>
            <dt>Community (Louvain)</dt><dd>{node.community ?? "–"}</dd>
            <dt>PageRank</dt><dd>{node.pagerank != null ? node.pagerank.toFixed(2) : "–"}</dd>
            <dt>Betweenness</dt><dd>{node.choke != null ? node.choke.toFixed(2) : "–"}</dd>
            <dt>Connections</dt><dd>{data.edges.filter((e) => e.src === node.id || e.dst === node.id).length}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}
