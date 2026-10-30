import { useEffect, useState } from "react";
import { Info } from "./parts.jsx";
import { getExposure, simulateExposure } from "./api.js";
import Explore from "./Explore.jsx";

const SCOPES = [
  { id: "low_trust", label: "From low-trust machines", hint: "Guest, intern and internet-facing machines" },
  { id: "all", label: "From anything", hint: "If any machine, account or agent were compromised" },
];
const plural = (n, one, many = one + "s") => (n === 1 ? one : many);

// attack paths before any attack: the company-wide picture (how many critical assets are reachable, which fixes cut
// the most, the choke points) above the per-system explorer. a choke point clicked here opens below.
export default function AttackPaths({ onError }) {
  const [scope, setScope] = useState("low_trust");
  const [data, setData] = useState(null);
  const [sim, setSim] = useState(null);
  const [focus, setFocus] = useState("laptop-42");

  useEffect(() => {
    setSim(null);
    getExposure(scope).then(setData).catch((e) => onError(e.message));
  }, [scope]); // eslint-disable-line

  const runSim = async (rec) => {
    if (sim?.rec === rec) { setSim(null); return; }
    try {
      const body = rec.kind === "cut" ? { scope, edges: rec.edges.map((e) => ({ src: e.src, dst: e.dst })) } : { scope, nodes: [rec.id] };
      setSim({ rec, result: await simulateExposure(body) });
    } catch (e) { onError(e.message); }
  };

  const reach = data?.pairs;
  const current = sim ? sim.result.pairs_after : reach?.reachable;
  return (
    <>
      <section className="ap-band">
        <div className="panel ap-sum">
          <div className="scope-switch">
            {SCOPES.map((s) => <button key={s.id} className={scope === s.id ? "on" : ""} title={s.hint} onClick={() => setScope(s.id)}>{s.label}</button>)}
          </div>
          {data && (
            <div className={`big-stat ${sim ? (current === 0 ? "cleared" : "reduced") : ""}`}>
              <div className="big-stat-v">{current}</div>
              <div className="big-stat-l">
                of {reach.possible} start-to-critical pairs {sim ? "still reachable after this fix" : "reachable before any attack"}
                <Info text="Pairs of a starting point and a critical asset that an attacker could connect, worked out from permissions, sessions and logins." />
              </div>
            </div>
          )}
          {data && (
            <div className="ap-chokes">
              <span className="ap-label">Choke points<Info text="Systems that many attack paths pass through. Click one to see what it reaches." /></span>
              {data.chokepoints.slice(0, 6).map((c) => (
                <button key={c.id} className={`ap-chip ${focus === c.id ? "on" : ""}`} onClick={() => setFocus(c.id)}>{c.id}<b>{c.paths_through}</b></button>
              ))}
            </div>
          )}
        </div>
        <div className="panel ap-fixes">
          <div className="ap-label">Fixes that cut the most paths<Info text="Each fix is recomputed on the graph to count the pairs it really cuts. Click one to apply it on paper." /></div>
          <ul className="recs">
            {(data?.recommendations || []).slice(0, 3).map((r, i) => {
              const active = sim?.rec === r;
              const res = active ? sim.result : null;
              return (
                <li key={i} className={active ? "on" : ""} onClick={() => runSim(r)}>
                  <div className="rec-top"><span className="rec-title">{r.title}</span>
                    <span className="rec-cut">{Math.round((res?.share_cut ?? r.share_cut) * 100)}%</span></div>
                  <div className="rec-sub">cuts {res?.pairs_cut ?? r.pairs_cut} of {res?.pairs_before ?? reach.reachable} {plural(res?.pairs_before ?? reach.reachable, "pair")}</div>
                  {active && r.kind === "cut" && <ul className="rec-edges">{r.edges.map((e, j) => <li key={j}>{e.action}</li>)}</ul>}
                </li>
              );
            })}
          </ul>
        </div>
      </section>
      <Explore onError={onError} focus={focus} onFocus={setFocus} />
    </>
  );
}
