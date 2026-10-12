import { useEffect, useMemo, useState } from "react";
import { getAlerts, getBlastRadius, getIncident, setVerdict, writeStory } from "./api.js";
import { SEVERITY_RANK } from "./tactics.js";
import RingGraph from "./RingGraph.jsx";
import Logo from "./Logo.jsx";
import ThemeToggle from "./Theme.jsx";
import Tour, { tourSeen } from "./Tour.jsx";
import { AlertStrip, MiniBar, ReasonBars, StageTimeline } from "./parts.jsx";

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [sortBy, setSortBy] = useState("score");
  const [selected, setSelected] = useState(null);
  const [blast, setBlast] = useState(null);
  const [incident, setIncident] = useState(null);
  const [story, setStory] = useState(null);
  const [node, setNode] = useState(null);
  const [maxHop, setMaxHop] = useState(3);
  const [touring, setTouring] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const load = () => getAlerts().then(setAlerts).catch((e) => setError(`Could not reach the backend server. ${e.message}`));
  useEffect(() => { load(); }, []);
  useEffect(() => { if (!tourSeen()) setTouring(true); }, []);
  useEffect(() => { if (alerts.length && !selected) open(alerts[0]); }, [alerts]); // eslint-disable-line

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
    const multi = Object.values(incidents).filter((g) => g.length > 1);
    const top = Object.entries(incidents).sort((a, b) => Math.max(...b[1].map((x) => x.score)) - Math.max(...a[1].map((x) => x.score)))[0];
    return {
      alerts: alerts.length,
      incidents: multi.length,
      near: alerts.filter((a) => (a.breakdown?.hops || 0) > 0).length,
      newRoutes: alerts.filter((a) => (a.breakdown?.never_taken || 0) > 0).length,
      top: top ? { id: top[0], size: top[1].length } : null,
    };
  }, [alerts]);

  async function open(alert) {
    setSelected(alert); setStory(null); setNode(null); setError(null);
    try {
      const [b, i] = await Promise.all([getBlastRadius(alert.id), getIncident(alert.incident_id)]);
      setBlast(b); setIncident(i);
    } catch (e) { setError(e.message); }
  }

  const draftStory = async () => {
    setBusy(true);
    try { setStory(await writeStory(incident.id)); } catch (e) { setError(e.message); }
    setBusy(false);
  };

  const mark = async (status) => {
    await setVerdict(selected.id, status);
    setSelected({ ...selected, status });
    load();
  };

  const nodeInfo = node && blast?.nodes.find((n) => n.id === node);
  const pathEnd = blast?.attack_path?.nodes?.at(-1);

  return (
    <div className="dash">
      <nav className="dnav">
        <a className="brand" href="#/"><Logo />GraphOps</a>
        <span className="tag">Sample organisation · synthetic data</span>
        <button className="tour-btn" onClick={() => setTouring(true)}>Take the tour</button>
        <ThemeToggle />
        <div className="sort" data-tour="sort">
          <span>Rank alerts by</span>
          <button className={sortBy === "score" ? "on" : ""} onClick={() => setSortBy("score")}>GraphOps score</button>
          <button className={sortBy === "severity" ? "on" : ""} onClick={() => setSortBy("severity")}>Severity only</button>
        </div>
      </nav>
      {error && <div className="error">{error}</div>}
      {touring && <Tour onClose={() => setTouring(false)} />}

      <section className="kpis" data-tour="kpis">
        <div className="kpi"><div className="kpi-k"><i />Alerts</div><div className="kpi-v">{kpis.alerts}</div><div className="kpi-l">today, none hidden</div></div>
        <div className="kpi"><div className="kpi-k"><i />Incidents</div><div className="kpi-v">{kpis.incidents}</div><div className="kpi-l">groups of linked alerts</div></div>
        <div className="kpi tint"><div className="kpi-k"><i />Near critical assets</div><div className="kpi-v">{kpis.near}</div><div className="kpi-l">alerts within 3 steps of a critical asset</div></div>
        <div className="kpi warn"><div className="kpi-k"><i />New routes</div><div className="kpi-v">{kpis.newRoutes}</div><div className="kpi-l">{kpis.newRoutes === 1 ? "alert" : "alerts"} on a route never used before</div></div>
      </section>

      <div data-tour="strip"><AlertStrip alerts={alerts} incidentId={incident?.id} selectedId={selected?.id} onPick={open} /></div>

      <main className="dmain">
        <section className="panel inbox" data-tour="inbox">
          <div className="panel-head">
            <h2>Alert inbox</h2>
            <small>{sortBy === "score" ? "sorted by graph position" : "sorted by the tools' severity"}</small>
          </div>
          <ol>
            {shown.map((a, i) => {
              const moved = sortBy === "severity" ? scoreRank[a.id] : sevRank[a.id];
              return (
                <li key={a.id} className={`${selected?.id === a.id ? "sel" : ""} ${incident && a.incident_id === incident.id ? "inc" : ""}`} onClick={() => open(a)}>
                  <div className="row1">
                    <span className="rank">{incident && a.incident_id === incident.id && <i className="inc-dot" title="part of the selected incident" />}#{i + 1}</span>
                    <span className="score">{Math.round(a.score)}</span>
                    <span className="name">{a.name}</span>
                  </div>
                  <div className="row2">
                    <span className={`sev ${a.severity}`}>{a.severity}</span>
                    <span className="who">{a.involves.join(" · ")}</span>
                    <span className="time">{a.time.slice(11, 16)}</span>
                    {a.status !== "new" && <span className={`verdict ${a.status}`}>{a.status === "real" ? "real" : "false alarm"}</span>}
                  </div>
                  <MiniBar breakdown={a.breakdown} />
                  {moved !== i + 1 && <div className="moved">{sortBy === "score" ? `#${moved} when sorted by severity` : `#${moved} in GraphOps`}</div>}
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
                  {nodeInfo.zone && <><dt>Zone</dt><dd>{nodeInfo.zone.replace("_", " ")}</dd></>}
                  {nodeInfo.owner && <><dt>Owner</dt><dd>{nodeInfo.owner}</dd></>}
                </dl>
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
                <button className={selected.status === "false" ? "on false" : ""} onClick={() => mark("false")}>False alarm</button>
              </div>

              <div data-tour="why">
                <h3>Why it ranks here</h3>
                <ReasonBars breakdown={selected.breakdown} />
              </div>

              {incident && (
                <>
                  <h3>Incident {incident.id} <small>{incident.alerts.length} linked alert{incident.alerts.length > 1 ? "s" : ""}</small></h3>
                  <StageTimeline alerts={incident.alerts} selectedId={selected.id} />
                  <button className="btn primary block" disabled={busy} onClick={draftStory}>{busy ? "Writing the story..." : "Draft the incident story with AI"}</button>
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
    </div>
  );
}
