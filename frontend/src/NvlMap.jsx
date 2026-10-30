import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { InteractiveNvlWrapper } from "@neo4j-nvl/react";
import { COMMUNITY_COLOR, groupColor, groupName, KIND_COLOR, LOCATION_COLOR, topBy } from "./GraphMap.jsx";

const CRITICAL = "#F16667";

// mix two hex colours: 0 gives a, 1 gives b. used to shade nodes by an algorithm score.
function ramp(a, b, t) {
  const x = (h, i) => parseInt(h.slice(1 + 2 * i, 3 + 2 * i), 16);
  const k = Math.max(0, Math.min(1, t));
  return "#" + [0, 1, 2].map((i) => Math.round(x(a, i) + (x(b, i) - x(a, i)) * k).toString(16).padStart(2, "0")).join("");
}

const MUTED = { dark: "#3A3D4A", light: "#D5D7DE" };

// influence and choke-point views keep the node-type groups and colours, mute everything but the top few nodes
// and ring those, so the answer stands out instead of a gradient nobody can read
function color(n, mode, top, dark) {
  if (mode === "community") return n.critical ? CRITICAL : n.community ? COMMUNITY_COLOR[(n.community - 1) % COMMUNITY_COLOR.length] : (dark ? MUTED.dark : MUTED.light);
  if (mode === "zones") return n.critical ? CRITICAL : LOCATION_COLOR[n.location] || LOCATION_COLOR.onprem;
  if ((mode === "choke" || mode === "pagerank") && !top.has(n.id)) return n.critical ? ramp(CRITICAL, dark ? "#111018" : "#ffffff", 0.55) : (dark ? MUTED.dark : MUTED.light);
  if (mode === "choke") return "#FFB020";
  if (n.critical) return CRITICAL;
  return KIND_COLOR[n.kind] || "#A5ABB6";
}

function size(n, mode, top) {
  if ((mode === "pagerank" || mode === "choke") && top.has(n.id)) return 48;
  return n.critical ? 44 : 36;
}

// the whole graph drawn with neo4j's own visualization library (nvl). drag, zoom and pan; click a node for its
// algorithm scores. nvl is licensed for use with neo4j aura, so the graph tab only uses it when the backend
// reports an aura database.
export default function NvlMap({ data, mode, path, dark }) {
  const nvl = useRef(null);
  const bg = dark ? "#111018" : "#ffffff";
  const [picked, setPicked] = useState(null);
  const onPath = useMemo(() => new Set(path?.ids || []), [path]);
  const pathRel = useMemo(() => new Set((path?.ids || []).slice(1).map((id, i) => `${path.ids[i]}>${id}`)), [path]);

  // nvl's clustering, as in neo4j's own clustering example: the force layout pulls each kind of node together
  // and draws a soft outline and halo around the group. nvl expects stable references for these options.
  // groups follow the view: communities in the communities view, locations in the location view, otherwise node
  // type. critical assets always form their own group so the targets sit together.
  const groupOf = useMemo(() => Object.fromEntries(data.nodes.map((n) => [n.id,
    n.critical ? "critical" : mode === "community" ? (n.community ? `c${n.community}` : "none") : mode === "zones" ? n.location : n.kind])), [data, mode]);
  const top = useMemo(() => new Set(mode === "choke" ? topBy(data.nodes, "choke").map((n) => n.id) : mode === "pagerank" ? topBy(data.nodes, "pagerank").map((n) => n.id) : []), [data, mode]);
  const clusterBy = useCallback((id) => groupOf[id], [groupOf]);
  const layoutOptions = useMemo(() => ({ clustering: { clusterBy, drawOutline: true, drawHalo: true } }), [clusterBy]);

  // the names that matter are drawn as overlay labels (below), so those nodes carry no canvas caption -
  // everything else keeps one for when the viewer zooms in
  const named = useMemo(() => new Set(data.nodes
    .filter((n) => n.critical || top.has(n.id) || n.kind === "AIAgent" || n.kind === "Internet").map((n) => n.id)), [data, top]);
  const nodes = useMemo(() => data.nodes.map((n) => ({
    id: n.id, caption: named.has(n.id) ? undefined : n.id, captionSize: 3, color: color(n, mode, top, dark), size: size(n, mode, top),
    selected: onPath.has(n.id) || picked === n.id, disabled: !!path && !onPath.has(n.id),
  })), [data, mode, path, onPath, picked, top, dark, named]);
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

  const fit = () => nvl.current?.fit(data.nodes.map((n) => n.id));
  const zoomBy = (f) => nvl.current && nvl.current.setZoom(nvl.current.getScale() * f);

  // zoom to fit once the force layout has had time to settle, and again when the graph changes
  useEffect(() => {
    const t = setTimeout(() => fit(), 600);
    return () => clearTimeout(t);
  }, [data]);

  // overlay chrome, kept in place over the canvas as the layout settles, zooms and pans: a caption above each
  // group, a dashed ring around the top-ranked nodes, and a name under every node that matters - critical
  // assets, the ranked answers and the ai agents - so the picture explains itself without hovering
  const [labels, setLabels] = useState([]);
  const [rings, setRings] = useState([]);
  const [names, setNames] = useState([]);
  const [hover, setHover] = useState(null);
  const byId = useMemo(() => Object.fromEntries(data.nodes.map((n) => [n.id, n])), [data]);
  useEffect(() => {
    let raf, last = "";
    const tick = () => {
      const groups = {};
      for (const n of nvl.current?.getNodes?.() || []) {
        const g = groupOf[n.id];
        if (!g || !n.clientPosition) continue;
        const b = (groups[g] ||= { x: 0, top: Infinity, count: 0 });
        b.x += n.clientPosition.x; b.top = Math.min(b.top, n.clientPosition.y); b.count += 1;
      }
      const out = Object.entries(groups).filter(([, b]) => b.count > 1)
        .map(([g, b]) => ({ g, x: b.x / b.count, y: b.top - 26, count: b.count }));
      const scale = nvl.current?.getScale?.() || 1;
      const rs = (nvl.current?.getNodes?.() || []).filter((n) => top.has(n.id) && n.clientPosition)
        .map((n) => ({ id: n.id, x: n.clientPosition.x, y: n.clientPosition.y, r: 48 * scale + 8 }));
      const nm = (nvl.current?.getNodes?.() || []).filter((n) => named.has(n.id) && !top.has(n.id) && n.clientPosition)
        .map((n) => ({ id: n.id, x: n.clientPosition.x, y: n.clientPosition.y + size(byId[n.id], mode, top) * scale + 6, crit: !!byId[n.id]?.critical }));
      const key = [...out.map((l) => `${l.g}:${Math.round(l.x)}:${Math.round(l.y)}`),
        ...rs.map((r) => `${r.id}:${Math.round(r.x)}:${Math.round(r.y)}:${Math.round(r.r)}`),
        ...nm.map((n) => `${n.id}:${Math.round(n.x)}:${Math.round(n.y)}`)].join("|");
      if (key !== last) { last = key; setLabels(out); setRings(rs); setNames(nm); }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [groupOf, mode, top, named, byId]);

  const node = picked && data.nodes.find((n) => n.id === picked);
  return (
    <div className="nvl-wrap">
      <InteractiveNvlWrapper
        ref={nvl}
        nodes={nodes}
        rels={rels}
        nvlOptions={{ layout: "forceDirected", layoutOptions, renderer: "canvas", disableTelemetry: true, minZoom: 0.05, maxZoom: 4, allowDynamicMinZoom: true,
          styling: { selectedBorderColor: CRITICAL, disabledItemColor: dark ? "#2A2C36" : "#E4E5EA", disabledItemFontColor: dark ? "#55586A" : "#A8ABB6" } }}
        nvlCallbacks={{ onLayoutDone: fit }}
        mouseEventCallbacks={{
          onZoom: true, onPan: true, onDrag: true,
          onHover: (el, hits, evt) => {
            const n = hits?.nodes?.[0]?.data;
            setHover(n ? { id: n.id, x: evt.offsetX, y: evt.offsetY } : null);
          },
          onNodeClick: (n) => setPicked(n.id === picked ? null : n.id),
          onCanvasClick: () => setPicked(null),
        }}
      />
      {labels.map((l) => (
        <div key={l.g} className={`nvl-group ${l.g === "critical" ? "crit" : ""}`} style={{ left: l.x, top: l.y }}>
          {groupColor(l.g, mode) && <i style={{ background: groupColor(l.g, mode) }} />}
          {groupName(l.g)} · {l.count}
        </div>
      ))}
      {rings.map((r) => (
        <div key={r.id} className={`nvl-ring ${mode}`} style={{ left: r.x, top: r.y, width: 2 * r.r, height: 2 * r.r }}>
          <span>{r.id}</span>
        </div>
      ))}
      {names.map((n) => (
        <div key={n.id} className={`nvl-label ${n.crit ? "crit" : ""}`} style={{ left: n.x, top: n.y }}>{n.id}</div>
      ))}
      {hover && (
        <div className="nvl-hover" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <i style={{ background: color(byId[hover.id] || {}, mode, top, dark) }} />
          <b>{hover.id}</b>
          <small>{byId[hover.id]?.kind}{byId[hover.id]?.critical ? " · critical" : ""}</small>
        </div>
      )}
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
