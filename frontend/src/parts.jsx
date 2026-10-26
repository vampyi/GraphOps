import { useState } from "react";
import { TACTICS } from "./tactics.js";

export const REASON_LABELS = {
  hops: "Close to a critical asset",
  blast: "Critical assets within 3 hops",
  linked: "Linked to other alerts",
  never_taken: "Route never used before",
  stages: "Follows attack stages in order",
  choke: "Sits on a choke point",
  severity: "Tool's own severity",
};
export const MAX_POINTS = { hops: 25, blast: 15, linked: 20, never_taken: 15, stages: 15, choke: 5, severity: 5 };

// how many points each ranking question added to the score
export function ReasonBars({ breakdown }) {
  return (
    <div className="reason-bars">
      {Object.keys(MAX_POINTS).map((k) => {
        const v = breakdown?.[k] || 0;
        return (
          <div key={k} className={`rbar ${v > 0 ? "on" : ""}`}>
            <span className="rbar-label">{REASON_LABELS[k]}</span>
            <span className="rbar-track"><span className="rbar-fill" style={{ width: `${(v / MAX_POINTS[k]) * 100}%` }} /></span>
            <span className="rbar-val">{v > 0 ? `+${Math.round(v)}` : "0"}</span>
          </div>
        );
      })}
    </div>
  );
}

// a thin stacked bar showing the same breakdown at a glance
export function MiniBar({ breakdown }) {
  return (
    <div className="minibar">
      {Object.keys(MAX_POINTS).map((k) => (
        <span key={k} className={`seg ${k}`} style={{ width: `${breakdown?.[k] || 0}%` }} title={`${REASON_LABELS[k]}: +${Math.round(breakdown?.[k] || 0)}`} />
      ))}
    </div>
  );
}

// every alert on one time strip, with the selected incident lit up
export function AlertStrip({ alerts, incidentId, selectedId, onPick }) {
  const [tip, setTip] = useState(null);
  if (!alerts.length) return null;
  // alert times have no timezone, so read them as plain clock times
  const clock = (iso) => { const [h, m] = iso.slice(11, 16).split(":").map(Number); return h * 60 + m; };
  const times = alerts.map((a) => clock(a.time));
  const t0 = Math.min(...times), t1 = Math.max(...times);
  const span = t1 - t0 || 1;
  const hours = [];
  for (let t = Math.ceil(t0 / 30) * 30; t <= t1; t += 30) hours.push(t);
  return (
    <div className="strip">
      <div className="strip-title">Today's alerts over time <small>dot size = score{incidentId ? `, lit = ${incidentId}` : ""}</small></div>
      <div className="strip-track">
        {hours.map((t) => (
          <span key={t} className={`strip-hour ${t % 60 ? "half" : ""}`} style={{ left: `${((t - t0) / span) * 100}%` }}>{String(Math.floor(t / 60)).padStart(2, "0")}:{t % 60 ? "30" : "00"}</span>
        ))}
        {alerts.map((a) => {
          const x = ((clock(a.time) - t0) / span) * 100;
          const size = 6 + (a.score / 100) * 16;
          const lit = incidentId && a.incident_id === incidentId;
          return (
            <button
              key={a.id}
              className={`strip-dot ${lit ? "lit" : ""} ${a.id === selectedId ? "sel" : ""}`}
              style={{ left: `${x}%`, width: size, height: size }}
              onMouseEnter={() => setTip({ a, x })}
              onMouseLeave={() => setTip(null)}
              onClick={() => onPick(a)}
            />
          );
        })}
        {tip && <StripTip {...tip} />}
      </div>
    </div>
  );
}

function StripTip({ a, x }) {
  const top = Object.entries(a.breakdown || {}).filter(([k]) => k !== "severity").sort((p, q) => q[1] - p[1])[0];
  return (
    <div className="strip-tip" style={{ left: `clamp(125px, ${x}%, calc(100% - 125px))` }}>
      <div className="tt-time">{a.time.slice(11, 16)} · {a.source_tool}</div>
      <div className="tt-name">{a.name}</div>
      <div className="tt-row">Score <b>{Math.round(a.score)}</b> · severity <b>{a.severity}</b></div>
      <div className="tt-row">On <b>{a.involves.join(", ")}</b></div>
      <div className="tt-row">Incident <b>{a.incident_id}</b>{top && top[1] > 0 ? <> · biggest reason <b>{REASON_LABELS[top[0]].toLowerCase()}</b></> : null}</div>
    </div>
  );
}

export function StageTimeline({ alerts, selectedId }) {
  return (
    <ol className="stages">
      {alerts.map((a) => (
        <li key={a.id} className={a.id === selectedId ? "sel" : ""}>
          <span className="stage-dot" />
          <div>
            <div className="stage-top"><span className="stage-time">{a.time.slice(11, 16)}</span><span className="stage-tag">{TACTICS[a.tactic_id] || "No stage tag"}</span></div>
            <div className="stage-name">{a.name}</div>
          </div>
        </li>
      ))}
    </ol>
  );
}

// a small markdown renderer for incident reports. the markdown is produced by our own backend, so we only
// handle the blocks it emits: headings, GFM tables, bullet lists, a rule and paragraphs, with inline bold,
// italic and code.
function inline(text, key) {
  const parts = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g;
  let last = 0, m, i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith("**")) parts.push(<strong key={`${key}-${i}`}>{t.slice(2, -2)}</strong>);
    else if (t.startsWith("`")) parts.push(<code key={`${key}-${i}`}>{t.slice(1, -1)}</code>);
    else parts.push(<em key={`${key}-${i}`}>{t.slice(1, -1)}</em>);
    last = m.index + t.length; i++;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function renderMarkdown(md) {
  const lines = md.split("\n");
  const out = [];
  let i = 0, k = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("## ")) { out.push(<h4 key={k++}>{inline(line.slice(3), k)}</h4>); i++; }
    else if (line.startsWith("# ")) { out.push(<h3 key={k++}>{inline(line.slice(2), k)}</h3>); i++; }
    else if (line.startsWith("|")) {
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) { rows.push(lines[i]); i++; }
      const cells = (r) => r.split("|").slice(1, -1).map((c) => c.trim());
      const header = cells(rows[0]);
      const body = rows.slice(2).map(cells);
      out.push(
        <table key={k++} className="md-table">
          <thead><tr>{header.map((h, j) => <th key={j}>{inline(h, `${k}h${j}`)}</th>)}</tr></thead>
          <tbody>{body.map((r, ri) => <tr key={ri}>{r.map((c, ci) => <td key={ci}>{inline(c, `${k}r${ri}c${ci}`)}</td>)}</tr>)}</tbody>
        </table>);
    }
    else if (line.startsWith("- ")) {
      const items = [];
      while (i < lines.length && lines[i].startsWith("- ")) { items.push(lines[i].slice(2)); i++; }
      out.push(<ul key={k++}>{items.map((it, j) => <li key={j}>{inline(it, `${k}i${j}`)}</li>)}</ul>);
    }
    else if (line.trim() === "---") { out.push(<hr key={k++} />); i++; }
    else if (line.trim() === "") { i++; }
    else { out.push(<p key={k++}>{inline(line, k)}</p>); i++; }
  }
  return out;
}

export function ReportModal({ report, onClose }) {
  const copy = () => { try { navigator.clipboard.writeText(report.markdown); } catch { /* clipboard blocked */ } };
  return (
    <div className="modal" role="dialog" aria-label="Incident report" onClick={onClose}>
      <div className="modal-card report-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <span>Incident report</span>
          <div>
            <button className="btn small" onClick={copy}>Copy Markdown</button>
            <button className="btn small" onClick={onClose}>Close</button>
          </div>
        </div>
        <div className="report-body">{renderMarkdown(report.markdown)}</div>
      </div>
    </div>
  );
}

// a small "i" that explains a label on hover, keyboard focus or tap, so explanations stay off the screen until asked for
export function Info({ text, align = "left" }) {
  return (
    <span className={`info ${align}`}>
      <button type="button" className="info-btn" aria-label={text}>i</button>
      <span className="info-tip" role="tooltip">{text}</span>
    </span>
  );
}

// citation chips. a connection id such as "laptop-42-RemoteLogon-server-7" reads as "laptop-42 → server-7"
const EDGE_ID = /^(.+)-(RemoteLogon|LoggedInto|HasSession|MemberOf|AdminTo|CanRDP|GenericAll|ConnectedTo)-(.+)$/;
export function Cites({ ids }) {
  return ids.map((c) => {
    const m = c.match(EDGE_ID);
    return <code key={c} title={m ? `${m[1]} ${m[2]} ${m[3]}` : undefined}>{m ? `${m[1]} → ${m[3]}` : c}</code>;
  });
}
