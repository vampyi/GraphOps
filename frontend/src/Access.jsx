import { useEffect, useState } from "react";
import { getAccess, getAccessOverview } from "./api.js";

const WINDOWS = [7, 30, 90];

export default function Access({ onError }) {
  const [days, setDays] = useState(30);
  const [overview, setOverview] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);

  useEffect(() => {
    getAccessOverview(days).then((o) => {
      setOverview(o);
      const first = o.identities[0]?.id;
      if (first) pick(first);
    }).catch((e) => onError(e.message));
  }, [days]); // eslint-disable-line

  const pick = async (id) => {
    setSelected(id);
    try { setDetail(await getAccess(id, days)); } catch (e) { onError(e.message); }
  };

  if (!overview) return <div className="view-loading">Comparing granted access with used access…</div>;

  return (
    <div className="access">
      <div className="acc-left panel">
        <div className="panel-head">
          <h2>Least-privilege gap</h2>
          <div className="window-switch">
            {WINDOWS.map((d) => <button key={d} className={days === d ? "on" : ""} onClick={() => setDays(d)}>{d}d</button>)}
          </div>
        </div>
        <p className="muted-p">Every account, ranked by the access it holds but has not used in {days} days. Unused access is risk with no benefit.</p>
        <ul className="acc-list">
          {overview.identities.map((r) => (
            <li key={r.id} className={selected === r.id ? "sel" : ""} onClick={() => pick(r.id)}>
              <div className="acc-row1">
                <span className="acc-id">{r.id}{r.service_account ? <span className="svc">service</span> : null}</span>
                <span className="acc-unused">{r.summary.unused} unused</span>
              </div>
              <GrantBar summary={r.summary} />
              {r.summary.unused_critical > 0 && <div className="acc-crit">{r.summary.unused_critical} unused critical</div>}
            </li>
          ))}
        </ul>
      </div>

      {detail && (
        <div className="acc-detail panel">
          <div className="panel-head"><h2>{detail.identity}</h2><small>{detail.kind} · access over the last {detail.days} days</small></div>
          <ShrinkingCircle summary={detail.summary} />
          <div className="acc-cols">
            <AccessColumn title="Granted" subtitle="entitled to reach" items={detail.granted} kind="granted" usedIds={new Set(detail.used.map((u) => u.id))} />
            <AccessColumn title="Used" subtitle="actually reached" items={detail.used} kind="used" />
          </div>
          {detail.unused.length > 0 && (
            <div className="acc-unused-block">
              <h3>Unused access — candidates to remove</h3>
              <div className="chips">{detail.unused.map((u) => <span key={u.id} className={`chip ${u.critical ? "crit" : ""}`}>{u.id}</span>)}</div>
            </div>
          )}
          {detail.used_without_grant.length > 0 && (
            <div className="acc-note">
              Used without a modelled grant: {detail.used_without_grant.map((u) => <code key={u.id}>{u.id}</code>)}. On real data this points at a default right GraphOps has not imported, such as the user's own device.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function GrantBar({ summary }) {
  const g = summary.granted || 1;
  const usedPct = (summary.used ? Math.min(summary.used, g) : 0) / g * 100;
  return (
    <div className="grant-bar" title={`${summary.used} used of ${summary.granted} granted`}>
      <span className="grant-used" style={{ width: `${usedPct}%` }} />
      <span className="grant-total">{summary.used}/{summary.granted}</span>
    </div>
  );
}

// the shrinking circle: the outer ring is everything granted, the solid inner disc is what is actually used.
// the gap between them is the access least privilege would remove.
function ShrinkingCircle({ summary }) {
  const R = 66, cx = 80, cy = 80;
  const granted = Math.max(summary.granted, 1);
  const usedR = Math.max(10, Math.sqrt(summary.used / granted) * R);
  return (
    <div className="shrink">
      <svg viewBox="0 0 160 160" className="shrink-svg" aria-hidden="true">
        <circle className="ring-granted" cx={cx} cy={cy} r={R} />
        <circle className="ring-used" cx={cx} cy={cy} r={usedR} />
      </svg>
      <div className="shrink-legend">
        <div><b>{summary.granted}</b> granted</div>
        <div className="used"><b>{summary.used}</b> used</div>
        <div className="unused"><b>{summary.unused}</b> unused{summary.unused_critical ? `, ${summary.unused_critical} critical` : ""}</div>
      </div>
    </div>
  );
}

function AccessColumn({ title, subtitle, items, kind, usedIds }) {
  return (
    <div className="acc-col">
      <div className="acc-col-head">{title} <span>{items.length}</span></div>
      <div className="acc-col-sub">{subtitle}</div>
      <ul>
        {items.map((it) => {
          const unused = kind === "granted" && usedIds && !usedIds.has(it.id);
          return (
            <li key={it.id} className={`${it.critical ? "crit" : ""} ${unused ? "unused" : ""}`}>
              <span className="ac-id">{it.id}</span>
              {it.critical && <span className="ac-tag">critical</span>}
              {kind === "used" && it.last_seen && <span className="ac-when">{it.last_seen.slice(5, 10)}</span>}
              {kind === "granted" && it.rights?.some((r) => r.via) && <span className="ac-via">via {it.rights.find((r) => r.via).via}</span>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
