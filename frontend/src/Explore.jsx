import { useEffect, useMemo, useState } from "react";
import { getEntities, getExplore, setControl } from "./api.js";
import RingGraph from "./RingGraph.jsx";
import { Info } from "./parts.jsx";

const MODES = [
  { id: "shortest", label: "Shortest path", tip: "Fewest steps from this system to each critical asset." },
  { id: "likely", label: "Most likely path", tip: "The route with the highest chance of success, multiplying each step's likelihood. It can be longer than the shortest." },
  { id: "open", label: "Needs securing", tip: "Paths with no recorded control on any step. An attacker could use them today." },
  { id: "secured", label: "Secured", tip: "Paths where at least one step has a recorded control, such as MFA or a removed permission." },
];
const KIND_LABEL = { User: "users", Group: "groups", Computer: "machines" };

// explore: pick any user, group or machine and see everything it can reach, with its attack paths to critical assets
export default function Explore({ onError }) {
  const [entities, setEntities] = useState([]);
  const [id, setId] = useState("laptop-42");
  const [data, setData] = useState(null);
  const [mode, setMode] = useState("shortest");
  const [picked, setPicked] = useState(null);
  const [node, setNode] = useState(null);
  const [note, setNote] = useState("");

  useEffect(() => { getEntities().then(setEntities).catch((e) => onError(e.message)); }, []); // eslint-disable-line
  const load = (eid = id) => getExplore(eid).then((d) => { setData(d); setPicked(null); }).catch((e) => onError(e.message));
  useEffect(() => { load(id); }, [id]); // eslint-disable-line

  const list = useMemo(() => {
    if (!data) return [];
    const p = data.paths;
    if (mode === "shortest") return p.filter((x) => x.shortest);
    if (mode === "likely") return p.filter((x) => x.most_likely);
    if (mode === "open") return p.filter((x) => !x.secured);
    return p.filter((x) => x.secured);
  }, [data, mode]);

  const graph = useMemo(() => data && {
    alert_id: data.entity.id, nodes: data.nodes, edges: data.edges, attack_path: null,
  }, [data]);
  const highlight = picked ? [picked.nodes] : list.map((p) => p.nodes);
  const maxHop = data ? Math.max(1, ...data.nodes.map((n) => n.hop)) : 3;

  const secure = async (step, on) => {
    try {
      await setControl({ src: step.src, type: step.type, dst: step.dst, secured: on, note: on ? note || "control recorded" : null });
      setNote("");
      load();
    } catch (e) { onError(e.message); }
  };

  return (
    <main className="explore">
      <section className="panel ex-side">
        <label className="ex-pick">
          <span>System</span>
          <select value={id} onChange={(e) => setId(e.target.value)}>
            {["Computer", "User", "Group"].map((k) => (
              <optgroup key={k} label={KIND_LABEL[k]}>
                {entities.filter((e) => e.kind === k).map((e) => <option key={e.id} value={e.id}>{e.id}{e.critical ? " (critical)" : ""}</option>)}
              </optgroup>
            ))}
          </select>
        </label>

        {data && (
          <>
            <div className="ex-sum">
              <div><b>{data.summary.reachable}</b><span>reachable<Info text="Systems an attacker holding this one could reach by following permissions, sessions and logins." /></span></div>
              <div className="crit"><b>{data.summary.critical}</b>critical</div>
              <div className="warn"><b>{data.summary.unsecured}</b>open paths</div>
            </div>
            <div className="ex-kinds">
              {Object.entries(data.summary.by_kind).map(([k, n]) => <span key={k}>{n} {KIND_LABEL[k] || k}</span>)}
            </div>

            <div className="ex-modes" role="group" aria-label="Paths to show">
              {MODES.map((m) => (
                <button key={m.id} className={mode === m.id ? "on" : ""} title={m.tip} onClick={() => { setMode(m.id); setPicked(null); }}>{m.label}</button>
              ))}
            </div>

            <ol className="ex-paths">
              {!list.length && <li className="ex-empty">{mode === "secured" ? "No secured paths yet" : "No paths"}</li>}
              {list.map((p, i) => (
                <li key={i} className={picked === p ? "on" : ""} onClick={() => setPicked(picked === p ? null : p)}>
                  <div className="ex-path-h">
                    <span className="tgt">{p.target}</span>
                    <span>{p.hops} step{p.hops > 1 ? "s" : ""} · {Math.round(p.likelihood * 100)}%</span>
                    {p.secured && <span className="sec-tag">secured</span>}
                  </div>
                  <div className="ex-path-n">{p.nodes.join(" → ")}</div>
                  {picked === p && (
                    <div className="ex-steps" onClick={(e) => e.stopPropagation()}>
                      {p.steps.map((st, j) => {
                        const ctl = p.controls.find((c) => c.src === st.src && c.dst === st.dst);
                        return (
                          <div key={j} className="ex-step">
                            <div><code>{st.src}</code> {st.step} <code>{st.dst}</code>
                              {st.technique && <span className="tech" title={st.technique_name}>{st.technique}</span>}
                            </div>
                            {ctl
                              ? <button className="linkish" onClick={() => secure(st, false)}>Secured: {ctl.note} · undo</button>
                              : <button className="linkish" onClick={() => secure(st, true)}>Mark step secured</button>}
                          </div>
                        );
                      })}
                      <input className="ex-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={120}
                        placeholder="Control note, e.g. MFA enforced" />
                    </div>
                  )}
                </li>
              ))}
            </ol>
          </>
        )}
      </section>

      <section className="panel ex-graph">
        <div className="panel-head">
          <h2>{data?.entity.id || "…"}</h2>
          <small>everything it can reach{picked ? ` · path to ${picked.target}` : ` · ${MODES.find((m) => m.id === mode).label.toLowerCase()}`}</small>
          <Info text={MODES.find((m) => m.id === mode).tip} />
        </div>
        <div className="graph-wrap">{graph && <RingGraph data={graph} maxHop={maxHop} highlight={highlight} selectedNode={node} onSelectNode={setNode} />}</div>
        <div className="legend">
          <span><i className="lg alerted" />selected system</span>
          <span><i className="lg hop" />reachable</span>
          <span><i className="lg critical" />critical asset</span>
          <span><i className="lg path" />highlighted path</span>
          <span><i className="lg secured" />secured step</span>
          <span className="shapes">● user ■ group ◆ computer</span>
        </div>
      </section>
    </main>
  );
}
