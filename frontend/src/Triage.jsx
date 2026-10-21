import { useEffect, useMemo, useState } from "react";
import { getBlastRadius, getIncident, getReport, patchAsset, patchIncident, setVerdict, writeStory } from "./api.js";
import { SEVERITY_RANK } from "./tactics.js";
import RingGraph from "./RingGraph.jsx";
import { AlertStrip, MiniBar, ReasonBars, StageTimeline, ReportModal } from "./parts.jsx";

const BLAST_MODES = [
  { id: "all", label: "All attack edges", hint: "Every route an attacker could follow" },
  { id: "granted", label: "Granted", hint: "Only permissions the identity holds" },
  { id: "used", label: "Used", hint: "Only logons actually seen in the last 30 days" },
];
const INCIDENT_STATUS = ["open", "investigating", "contained", "closed"];

export default function Triage({ alerts, changed, live, focusAlertId, onReload, onError }) {
  const [sortBy, setSortBy] = useState("score");
  const [selected, setSelected] = useState(null);
  const [blast, setBlast] = useState(null);
  const [blastMode, setBlastMode] = useState("all");
  const [incident, setIncident] = useState(null);
  const [story, setStory] = useState(null);
  const [report, setReport] = useState(null);
  const [node, setNode] = useState(null);
  const [maxHop, setMaxHop] = useState(3);
  const [busy, setBusy] = useState(false);

  // keep the selected alert pointing at the freshest copy as live updates arrive
  useEffect(() => {
    if (!selected) { if (alerts.length) open(alerts[0]); return; }
    const fresh = alerts.find((a) => a.id === selected.id);
    if (fresh && fresh !== selected) setSelected(fresh);
  }, [alerts]); // eslint-disable-line

  // the guided demo drives which alert is open (the attack as it climbs the inbox)
  useEffect(() => {
    if (!focusAlertId || focusAlertId === selected?.id) return;
    const a = alerts.find((x) => x.id === focusAlertId);
    if (a) open(a);
  }, [focusAlertId]); // eslint-disable-line

  const shown = useMemo(() => {
    const list = [...alerts];
    if (sortBy === "severity") list.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.time.localeCompare(b.time));
    return list;
  }, [alerts, sortBy]);

  const scoreRank = useMemo(() => Object.fromEntries(alerts.map((a, i) => [a.id, i + 1])), [alerts]);
  const sevRank = useMemo(() => {
    const s = [...alerts].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.time.localeCompare(b.time));
    return Object.fromEntries(s.map((a, i) => [a.id, i + 1]));
  }, [alerts]);

  const kpis = useMemo(() => {
    const incidents = {};
    alerts.forEach((a) => { (incidents[a.incident_id] ||= []).push(a); });
    return {
      alerts: alerts.length,
      incidents: Object.values(incidents).filter((g) => g.length > 1).length,
      near: alerts.filter((a) => (a.breakdown?.hops || 0) > 0).length,
      newRoutes: alerts.filter((a) => (a.breakdown?.never_taken || 0) > 0).length,
    };
  }, [alerts]);

  async function open(alert, mode = blastMode) {
    setSelected(alert); setStory(null); setNode(null);
    // fetch independently so a failure in one does not blank the other
    try { setBlast(await getBlastRadius(alert.id, mode)); } catch (e) { onError(`Could not load the blast radius: ${e.message}`); }
    if (alert.incident_id) {
      try { setIncident(await getIncident(alert.incident_id)); }
      catch (e) { setIncident(null); onError(`Could not load the incident: ${e.message}`); }
    } else {
      setIncident(null);
    }
  }

  async function changeMode(mode) {
    setBlastMode(mode);
    if (selected) {
      try { setBlast(await getBlastRadius(selected.id, mode)); } catch (e) { onError(e.message); }
    }
  }

  const draftStory = async () => {
    setBusy(true);
    try { setStory(await writeStory(incident.id)); } catch (e) { onError(e.message); }
    setBusy(false);
  };

  const mark = async (status) => {
    try {
      await setVerdict(selected.id, status, "analyst");
      onReload();
    } catch (e) { onError(e.message); }
  };

  const setStatus = async (status) => {
    try {
      await patchIncident(incident.id, { status });
      setIncident({ ...incident, status });
    } catch (e) { onError(e.message); }
  };

  const toggleCritical = async (n) => {
    try {
      const res = await patchAsset(n.id, { critical: !n.critical });
      onReload();
      if (selected) open({ ...selected }, blastMode);
      setNode(null);
      return res;
    } catch (e) { onError(e.message); }
  };

  const openReport = async () => {
    try { setReport(await getReport(incident.id)); } catch (e) { onError(e.message); }
  };

  const nodeInfo = node && blast?.nodes.find((n) => n.id === node);
  const pathEnd = blast?.attack_path?.nodes?.at(-1);
  const emptyLive = live.on && !alerts.length;

  return (
    <>
      <section className="kpis" data-tour="kpis">
        <div className="kpi"><div className="kpi-k"><i />Alerts</div><div className="kpi-v">{kpis.alerts}</div><div className="kpi-l">{live.on ? "arriving live, none hidden" : "today, none hidden"}</div></div>
        <div className="kpi"><div className="kpi-k"><i />Incidents</div><div className="kpi-v">{kpis.incidents}</div><div className="kpi-l">groups of linked alerts</div></div>
        <div className="kpi tint"><div className="kpi-k"><i />Near critical assets</div><div className="kpi-v">{kpis.near}</div><div className="kpi-l">alerts within 3 steps of a critical asset</div></div>
        <div className="kpi warn"><div className="kpi-k"><i />New routes</div><div className="kpi-v">{kpis.newRoutes}</div><div className="kpi-l">{kpis.newRoutes === 1 ? "alert" : "alerts"} on a route never used before</div></div>
      </section>

      {emptyLive
        ? <div className="live-empty">Replay started. Alerts will appear here as the day streams in…</div>
        : <div data-tour="strip"><AlertStrip alerts={alerts} incidentId={incident?.id} selectedId={selected?.id} onPick={open} /></div>}

      <main className="dmain">
        <section className="panel inbox" data-tour="inbox">
          <div className="panel-head">
            <h2>Alert inbox</h2>
            <div className="sort">
              <button className={sortBy === "score" ? "on" : ""} onClick={() => setSortBy("score")}>GraphOps score</button>
              <button className={sortBy === "severity" ? "on" : ""} onClick={() => setSortBy("severity")}>Severity only</button>
            </div>
          </div>
          <ol>
            {shown.map((a, i) => {
              const moved = sortBy === "severity" ? scoreRank[a.id] : sevRank[a.id];
              return (
                <li key={a.id} className={`${selected?.id === a.id ? "sel" : ""} ${incident && a.incident_id === incident.id ? "inc" : ""} ${changed.has(a.id) ? "flash" : ""}`} onClick={() => open(a)}>
                  <div className="row1">
                    <span className="rank">{incident && a.incident_id === incident.id && <i className="inc-dot" title="part of the selected incident" />}#{i + 1}</span>
                    <span className="score">{Math.round(a.score)}</span>
                    <span className="name">{a.name}</span>
                  </div>
                  <div className="row2">
                    <span className={`sev ${a.severity}`}>{a.severity}</span>
                    <span className="who">{a.involves.join(" · ")}</span>
                    <span className="time">{a.time.slice(11, 16)}</span>
                    {a.status && a.status !== "new" && <span className={`verdict ${a.status}`}>{a.status === "real" ? "real" : a.status === "benign" ? "benign" : "false alarm"}</span>}
                  </div>
                  <MiniBar breakdown={a.breakdown} />
                  {moved !== i + 1 && <div className="moved">{sortBy === "score" ? `#${moved} by severity` : `#${moved} in GraphOps`}</div>}
                </li>
              );
            })}
          </ol>
        </section>

        <section className="panel graph-panel" data-tour="graph">
          <div className="panel-head">
            <h2>Blast radius</h2>
            <small>what an attacker on this alert's machine or account could reach</small>
          </div>
          <div className="blast-modes" data-tour="modes">
            {BLAST_MODES.map((m) => (
              <button key={m.id} className={blastMode === m.id ? "on" : ""} title={m.hint} onClick={() => changeMode(m.id)}>{m.label}</button>
            ))}
          </div>
          <div className="hops" data-tour="hops">
            {[1, 2, 3].map((h) => {
              const within = blast ? blast.nodes.filter((n) => n.hop > 0 && n.hop <= h) : [];
              return (
                <button key={h} className={maxHop === h ? "on" : ""} onClick={() => setMaxHop(h)}>
                  {h} hop{h > 1 ? "s" : ""}
                  <span>{within.length} reachable{within.some((n) => n.critical) ? `, ${within.filter((n) => n.critical).length} critical` : ""}</span>
                </button>
              );
            })}
          </div>
          {blastMode !== "all" && <div className="mode-note">{blastMode === "granted" ? "Access this identity is entitled to." : "Access actually used in the last 30 days. The gap from “granted” is what least privilege removes."}</div>}
          {blast?.attack_path && (
            <div className="path-banner">
              <span className="path-dot" />
              Shortest attack path to <b>{pathEnd}</b>:{" "}
              {blast.attack_path.nodes.map((id, i) => (
                <span key={id}>{i > 0 && <em> {blast.attack_path.types[i - 1]} </em>}<code>{id}</code></span>
              ))}
            </div>
          )}
          <div className="graph-wrap">
            <RingGraph data={blast} selectedNode={node} onSelectNode={setNode} maxHop={maxHop} />
            {nodeInfo && (
              <div className="inspector">
                <button className="x" onClick={() => setNode(null)}>×</button>
                <div className="insp-kind">{nodeInfo.kind}{nodeInfo.critical ? " · critical asset" : ""}</div>
                <div className="insp-name">{nodeInfo.id}</div>
                <dl>
                  <dt>Hops from this alert</dt><dd>{nodeInfo.hop}</dd>
                  <dt>Steps to nearest critical asset</dt><dd>{nodeInfo.hops_to_critical ?? "none reachable"}</dd>
                  <dt>Critical assets within 3 hops</dt><dd>{nodeInfo.critical_within_3 ?? 0}</dd>
                  <dt>Choke point score</dt><dd>{nodeInfo.choke_score}</dd>
                  {nodeInfo.community != null && <><dt>Activity community</dt><dd>#{nodeInfo.community}</dd></>}
                  {nodeInfo.zone && <><dt>Zone</dt><dd>{nodeInfo.zone.replace("_", " ")}</dd></>}
                </dl>
                {nodeInfo.kind === "Computer" && (
                  <button className="btn small block" onClick={() => toggleCritical(nodeInfo)}>
                    {nodeInfo.critical ? "Unmark critical" : "Mark as critical asset"}
                  </button>
                )}
              </div>
            )}
          </div>
          <div className="legend">
            <span><i className="lg alerted" />on the alert</span>
            <span><i className="lg hop" />reachable</span>
            <span><i className="lg critical" />critical asset</span>
            <span><i className="lg path" />attack path</span>
            <span className="shapes">● user ■ group ◆ computer</span>
          </div>
        </section>

        <section className="panel side" data-tour="side">
          {selected && (
            <>
              <div className="sel-head">
                <div className="sel-score">{Math.round(selected.score)}</div>
                <div>
                  <h2>{selected.name}</h2>
                  <small>{selected.involves.join(" · ")} · {selected.time.slice(11, 16)} · {selected.source_tool}</small>
                </div>
              </div>
              <div className="verdicts">
                <button className={selected.status === "real" ? "on real" : ""} onClick={() => mark("real")}>Real attack</button>
                <button className={selected.status === "benign" ? "on benign" : ""} onClick={() => mark("benign")}>Benign</button>
                <button className={selected.status === "false" ? "on false" : ""} onClick={() => mark("false")}>False alarm</button>
              </div>
              <p className="verdict-note">“Benign” records real but allowed activity, so it is not counted as a miss.</p>

              <div data-tour="why">
                <h3>Why it ranks here</h3>
                <ReasonBars breakdown={selected.breakdown} />
              </div>

              {incident && (
                <>
                  <div className="inc-head">
                    <h3>Incident <small>{incident.alerts.length} linked alert{incident.alerts.length > 1 ? "s" : ""}{incident.lateral ? ` · lateral across ${incident.communities?.length} groups` : ""}</small></h3>
                    <select value={incident.status || "open"} onChange={(e) => setStatus(e.target.value)} aria-label="Incident status">
                      {INCIDENT_STATUS.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <StageTimeline alerts={incident.alerts} selectedId={selected.id} />
                  <div className="inc-actions">
                    <button className="btn primary" disabled={busy} onClick={draftStory}>{busy ? "Writing…" : "Draft story (AI)"}</button>
                    <button className="btn" onClick={openReport}>Incident report</button>
                  </div>
                  {story && (
                    <div className="story">
                      <div className="story-head">{story.source === "llm" ? "Drafted by AI. Needs analyst approval." : "AI is not available right now, so these are the incident's facts."}</div>
                      {story.sentences.map((s, i) => <p key={i}>{s.text} {s.cites.map((c) => <code key={c}>{c}</code>)}</p>)}
                      {story.dropped?.length > 0 && <div className="dropped">{story.dropped.length} sentence(s) removed for citing facts outside this incident.</div>}
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </section>
      </main>
      {report && <ReportModal report={report} onClose={() => setReport(null)} />}
    </>
  );
}
