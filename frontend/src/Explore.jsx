import { useEffect, useMemo, useState } from "react";
import { getEntities, getExplore, getVulnerabilities, refreshVulnerabilities, setControl } from "./api.js";
import RingGraph from "./RingGraph.jsx";
import { Info } from "./parts.jsx";

const MODES = [
  { id: "shortest", label: "Shortest path", tip: "Fewest steps from this system to each critical asset." },
  { id: "likely", label: "Most likely path", tip: "The route with the highest chance of success, multiplying each step's likelihood. It can be longer than the shortest." },
  { id: "open", label: "Needs securing", tip: "Paths with no recorded control on any step. An attacker could use them today." },
  { id: "secured", label: "Secured", tip: "Paths where at least one step has a recorded control, such as MFA or a removed permission." },
];
const KIND_LABEL = {
  User: "users", Group: "groups", Computer: "machines", AIAgent: "AI agents", CloudResource: "cloud resources",
  ServiceIdentity: "service identities", Tool: "agent tools", Internet: "internet",
};
const KIND_ONE = {
  User: "user", Group: "group", Computer: "machine", AIAgent: "AI agent", CloudResource: "cloud resource",
  ServiceIdentity: "service identity", Tool: "agent tool", Internet: "internet",
};
const PICK_ORDER = ["Internet", "Computer", "User", "Group", "AIAgent", "ServiceIdentity", "Tool", "CloudResource"];
const LOCATION_LABEL = { onprem: "on-premises", cloud: "cloud", external: "external" };

// explore: pick any user, group or machine and see everything it can reach, with its attack paths to critical assets
// focus/onFocus let the attack paths tab open a system here (for example a choke point clicked above)
export default function Explore({ onError, focus, onFocus }) {
  const [entities, setEntities] = useState([]);
  const [ownId, setOwnId] = useState("laptop-42");
  const id = focus ?? ownId;
  const setId = onFocus ?? setOwnId;
  const [data, setData] = useState(null);
  const [mode, setMode] = useState("shortest");
  const [picked, setPicked] = useState(null);
  const [node, setNode] = useState(null);
  const [note, setNote] = useState("");
  const [vulns, setVulns] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const loadVulns = () => getVulnerabilities().then(setVulns).catch(() => setVulns([]));
  useEffect(() => { loadVulns(); }, []);
  const refresh = async () => {
    setRefreshing(true);
    try { await refreshVulnerabilities(); await loadVulns(); await load(); } catch (e) { onError(e.message); }
    setRefreshing(false);
  };

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
            {PICK_ORDER.filter((k) => entities.some((e) => e.kind === k)).map((k) => (
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
              {Object.entries(data.summary.by_kind).map(([k, n]) => <span key={k}>{n} {n === 1 ? (KIND_ONE[k] || k) : (KIND_LABEL[k] || k)}</span>)}
            </div>
            <div className="ex-kinds loc">
              {Object.entries(data.summary.by_location || {}).map(([k, n]) => <span key={k} className={`loc-tag ${k}`}>{n} {LOCATION_LABEL[k] || k}</span>)}
              {data.entity.illustrative && <span className="loc-tag illus" title="An example AI agent built from documented patterns, not from real company data">illustrative</span>}
            </div>
            <VulnList vulns={vulns.filter((v) => v.host === (node || data.entity.id))} host={node || data.entity.id} onRefresh={refresh} refreshing={refreshing} />

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
          <span><i className="lg cloud" />cloud</span>
          <span><i className="lg kev" />known-exploited CVE</span>
          <span className="shapes">● user ■ group ◆ computer ⬢ AI agent ▲ tool ▬ cloud resource ○ service identity</span>
        </div>
      </section>
    </main>
  );
}

function VulnList({ vulns, host, onRefresh, refreshing }) {
  if (!vulns.length) return null;
  return (
    <div className="ex-vulns">
      <div className="ex-vulns-h">
        <span>Vulnerabilities on {host}<Info text="Serious CVEs for the software this machine runs: known exploited (CISA KEV) or CVSS 9+. From NIST NVD, CISA KEV and FIRST EPSS. This product uses the NVD API but is not endorsed or certified by the NVD." /></span>
        <button className="linkish" disabled={refreshing} onClick={onRefresh}>{refreshing ? "Refreshing…" : "Refresh"}</button>
      </div>
      {vulns.map((v) => (
        <a key={v.cve} className="ex-vuln" href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noreferrer">
          <span className="cve">{v.cve}</span>
          {v.kev && <span className="kev-tag" title={`Added to CISA KEV ${v.kev_added}`}>exploited</span>}
          <span className="meta">CVSS {v.cvss} · EPSS {v.epss != null ? (v.epss * 100).toFixed(v.epss > 0.1 ? 0 : 1) + "%" : "–"} · {v.software}</span>
        </a>
      ))}
      <div className="ex-vulns-f">Data as of {vulns[0].fetched?.slice(0, 10) || "–"}</div>
    </div>
  );
}
