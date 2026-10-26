import { useEffect, useMemo, useState } from "react";
import { getBlastRadius, getIncident, getLanguages, getReport, patchAsset, patchIncident, setVerdict, writeStory } from "./api.js";
import { SEVERITY_RANK } from "./tactics.js";
import RingGraph from "./RingGraph.jsx";
import { MiniBar, ReasonBars, StageTimeline, ReportModal } from "./parts.jsx";

const BLAST_MODES = [
  { id: "all", label: "All attack edges", hint: "Every route an attacker could follow" },
  { id: "granted", label: "Granted", hint: "Only permissions the identity holds" },
  { id: "used", label: "Used", hint: "Only logons actually seen in the last 30 days" },
];
const INCIDENT_STATUS = ["open", "investigating", "contained", "closed"];
const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = [
  { id: "new", label: "Not reviewed" },
  { id: "real", label: "Real" },
  { id: "benign", label: "Benign" },
  { id: "false", label: "False alarm" },
];
const SIGNALS = [
  { id: "near", label: "Near a critical asset", test: (a) => (a.breakdown?.hops || 0) > 0 },
  { id: "route", label: "New route", test: (a) => (a.breakdown?.never_taken || 0) > 0 },
  { id: "linked", label: "Linked to other alerts", test: (a) => (a.breakdown?.linked || 0) > 0 },
];
export const TRIAGE_TABS = [
  { id: "why", label: "Why it ranks" },
  { id: "blast", label: "Blast radius" },
  { id: "incident", label: "Incident" },
  { id: "story", label: "Story" },
];
const VERDICT_LABEL = { real: "real", benign: "benign", false: "false alarm" };

const bySeverity = (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.time.localeCompare(b.time);
const toggle = (set, v) => { const s = new Set(set); s.has(v) ? s.delete(v) : s.add(v); return s; };

export default function Triage({ alerts, changed, live, focusAlertId, onReload, onError }) {
  const [sortBy, setSortBy] = useState("score");
  const [query, setQuery] = useState("");
  const [sevF, setSevF] = useState(new Set());
  const [statusF, setStatusF] = useState(new Set());
  const [signalF, setSignalF] = useState(new Set());
  const [tab, setTab] = useState("why");
  const [selected, setSelected] = useState(null);
  const [blast, setBlast] = useState(null);
  const [blastMode, setBlastMode] = useState("all");
  const [incident, setIncident] = useState(null);
  const [story, setStory] = useState(null);
  const [report, setReport] = useState(null);
  const [node, setNode] = useState(null);
  const [maxHop, setMaxHop] = useState(3);
  const [busy, setBusy] = useState(false);
  const [lang, setLang] = useState("en-IN");
  const [languages, setLanguages] = useState([{ code: "en-IN", name: "English" }]);
  useEffect(() => { getLanguages().then((d) => setLanguages(d.languages)).catch(() => {}); }, []);

  // the guided tour switches tabs so it can point at what lives inside them
  useEffect(() => {
    const onTab = (e) => setTab(e.detail);
    window.addEventListener("graphops:tab", onTab);
    return () => window.removeEventListener("graphops:tab", onTab);
  }, []);

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

  const ordered = useMemo(() => (sortBy === "severity" ? [...alerts].sort(bySeverity) : alerts), [alerts, sortBy]);
  const scoreRank = useMemo(() => Object.fromEntries(alerts.map((a, i) => [a.id, i + 1])), [alerts]);
  const sevRank = useMemo(() => Object.fromEntries([...alerts].sort(bySeverity).map((a, i) => [a.id, i + 1])), [alerts]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return ordered.filter((a) =>
      (!sevF.size || sevF.has(a.severity)) &&
      (!statusF.size || statusF.has(a.status || "new")) &&
      [...signalF].every((id) => SIGNALS.find((s) => s.id === id).test(a)) &&
      (!q || [a.name, a.id, a.source_tool, ...a.involves].some((t) => String(t || "").toLowerCase().includes(q))));
  }, [ordered, query, sevF, statusF, signalF]);
  const filtering = query || sevF.size || statusF.size || signalF.size;
  const clearFilters = () => { setQuery(""); setSevF(new Set()); setStatusF(new Set()); setSignalF(new Set()); };

  const summary = useMemo(() => {
    const groups = {};
    alerts.forEach((a) => { (groups[a.incident_id] ||= []).push(a); });
    return {
      alerts: alerts.length,
      incidents: Object.values(groups).filter((g) => g.length > 1).length,
      near: alerts.filter(SIGNALS[0].test).length,
      routes: alerts.filter(SIGNALS[1].test).length,
      open: alerts.filter((a) => !a.status || a.status === "new").length,
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
    try { setStory(await writeStory(incident.id, lang)); } catch (e) { onError(e.message); }
    setBusy(false);
  };

  const mark = async (status) => {
    try { await setVerdict(selected.id, status, "analyst"); onReload(); } catch (e) { onError(e.message); }
  };

  const setStatus = async (status) => {
    try { await patchIncident(incident.id, { status }); setIncident({ ...incident, status }); } catch (e) { onError(e.message); }
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

  const emptyLive = live.on && !alerts.length;

  return (
    <>
      <section className="tri-summary" data-tour="kpis">
        <span><b>{summary.alerts}</b> alerts{live.on ? " arriving live" : " today"}, none hidden</span>
        <span><b>{summary.incidents}</b> incidents of linked alerts</span>
        <span className="tint"><b>{summary.near}</b> near a critical asset</span>
        <span className="warn"><b>{summary.routes}</b> on a new route</span>
        <span><b>{summary.open}</b> not reviewed</span>
      </section>

      <main className="tri">
        <section className="panel tri-list" data-tour="inbox">
          <div className="tri-tools" data-tour="filters">
            <input className="tri-search" type="search" placeholder="Search alerts, users, machines…" value={query}
              onChange={(e) => setQuery(e.target.value)} aria-label="Search alerts" />
            <FilterRow label="Severity">
              {SEVERITIES.map((s) => <Chip key={s} on={sevF.has(s)} cls={`sev-chip ${s}`} onClick={() => setSevF(toggle(sevF, s))}>{s}</Chip>)}
            </FilterRow>
            <FilterRow label="Verdict">
              {STATUSES.map((s) => <Chip key={s.id} on={statusF.has(s.id)} onClick={() => setStatusF(toggle(statusF, s.id))}>{s.label}</Chip>)}
            </FilterRow>
            <FilterRow label="Graph">
              {SIGNALS.map((s) => <Chip key={s.id} on={signalF.has(s.id)} onClick={() => setSignalF(toggle(signalF, s.id))}>{s.label}</Chip>)}
            </FilterRow>
            <div className="tri-count">
              <span>{filtering ? `Showing ${shown.length} of ${alerts.length}` : `${alerts.length} alerts`}</span>
              {filtering ? <button className="linkish" onClick={clearFilters}>Clear filters</button> : null}
              <div className="sort" role="group" aria-label="Sort order">
                <button className={sortBy === "score" ? "on" : ""} onClick={() => setSortBy("score")}>GraphOps score</button>
                <button className={sortBy === "severity" ? "on" : ""} onClick={() => setSortBy("severity")}>Severity only</button>
              </div>
            </div>
          </div>

          {emptyLive
            ? <div className="live-empty">Replay started. Alerts will appear here as the day streams in…</div>
            : !shown.length
              ? <div className="live-empty">No alerts match these filters.</div>
              : (
                <ol className="tri-rows">
                  {shown.map((a) => {
                    const rank = sortBy === "score" ? scoreRank[a.id] : sevRank[a.id];
                    const other = sortBy === "score" ? sevRank[a.id] : scoreRank[a.id];
                    const inInc = incident && a.incident_id === incident.id;
                    return (
                      <li key={a.id} className={`${selected?.id === a.id ? "sel" : ""} ${inInc ? "inc" : ""} ${changed.has(a.id) ? "flash" : ""}`}
                        onClick={() => open(a)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && open(a)}>
                        <span className="rank">#{rank}</span>
                        <span className="score">{Math.round(a.score)}</span>
                        <div className="row-main">
                          <div className="name">{inInc && <i className="inc-dot" title="part of the selected incident" />}{a.name}</div>
                          <div className="row-meta">
                            <span className={`sev ${a.severity}`}>{a.severity}</span>
                            <span>{a.time.slice(11, 16)}</span>
                            <span className="who">{a.involves.join(" · ")}</span>
                            {a.status && a.status !== "new" && <span className={`verdict ${a.status}`}>{VERDICT_LABEL[a.status]}</span>}
                          </div>
                          <MiniBar breakdown={a.breakdown} />
                        </div>
                        {other !== rank && <span className="moved" title={sortBy === "score" ? "where this alert would sit if sorted by severity" : "where GraphOps ranks this alert"}>#{other}<small>{sortBy === "score" ? "by severity" : "in GraphOps"}</small></span>}
                      </li>
                    );
                  })}
                </ol>
              )}
        </section>

        <section className="panel tri-detail" data-tour="side">
          {!selected ? <div className="live-empty">Pick an alert on the left.</div> : (
            <>
              <header className="det-head">
                <div className="sel-score" title="GraphOps score out of 100">{Math.round(selected.score)}</div>
                <div className="det-title">
                  <h2>{selected.name}</h2>
                  <div className="det-meta">
                    <span className={`sev ${selected.severity}`}>{selected.severity}</span>
                    <span>{selected.time.slice(11, 16)}</span>
                    <span>{selected.involves.join(" · ")}</span>
                    <span>{selected.source_tool}</span>
                    <span>#{scoreRank[selected.id]} in GraphOps, #{sevRank[selected.id]} by severity</span>
                  </div>
                </div>
                <div className="verdicts" aria-label="Verdict">
                  <button className={selected.status === "real" ? "on real" : ""} onClick={() => mark("real")}>Real attack</button>
                  <button className={selected.status === "benign" ? "on benign" : ""} onClick={() => mark("benign")} title="Real but allowed activity">Benign</button>
                  <button className={selected.status === "false" ? "on false" : ""} onClick={() => mark("false")}>False alarm</button>
                </div>
              </header>

              <nav className="det-tabs" role="tablist" data-tour="tabs">
                {TRIAGE_TABS.map((t) => (
                  <button key={t.id} role="tab" aria-selected={tab === t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
                    {t.label}
                    {t.id === "incident" && incident && <small>{incident.alerts.length}</small>}
                  </button>
                ))}
              </nav>

              <div className="det-body">
                {tab === "why" && <WhyTab alert={selected} />}
                {tab === "blast" && (
                  <BlastTab blast={blast} mode={blastMode} onMode={changeMode} maxHop={maxHop} onHop={setMaxHop}
                    node={node} onNode={setNode} onToggleCritical={toggleCritical} />
                )}
                {tab === "incident" && (
                  <IncidentTab incident={incident} selectedId={selected.id} onStatus={setStatus} onReport={openReport} />
                )}
                {tab === "story" && <StoryTab incident={incident} story={story} busy={busy} onDraft={draftStory} lang={lang} onLang={setLang} languages={languages} />}
              </div>
            </>
          )}
        </section>
      </main>
      {report && <ReportModal report={report} onClose={() => setReport(null)} />}
    </>
  );
}

function FilterRow({ label, children }) {
  return <div className="frow"><span className="frow-l">{label}</span><div className="fchips">{children}</div></div>;
}

function Chip({ on, cls = "", onClick, children }) {
  return <button className={`fchip ${cls} ${on ? "on" : ""}`} aria-pressed={on} onClick={onClick}>{children}</button>;
}

function WhyTab({ alert }) {
  return (
    <div className="tab-pane" data-tour="why">
      <p className="tab-lead">The score adds up seven questions. Six are answered from the graph; the last is the tool's own severity. Longer bars added more points.</p>
      <ReasonBars breakdown={alert.breakdown} />
      {alert.reasons?.length > 0 && (
        <>
          <h3>In plain words</h3>
          <ul className="reasons">{alert.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </>
      )}
    </div>
  );
}

function BlastTab({ blast, mode, onMode, maxHop, onHop, node, onNode, onToggleCritical }) {
  const nodeInfo = node && blast?.nodes.find((n) => n.id === node);
  const pathEnd = blast?.attack_path?.nodes?.at(-1);
  return (
    <div className="tab-pane blast" data-tour="graph">
      <p className="tab-lead">What an attacker holding this alert's machine or account could reach. Click a shape for details.</p>
      <div className="blast-controls">
        <div className="segctl" data-tour="modes" role="group" aria-label="Which access to follow">
          {BLAST_MODES.map((m) => (
            <button key={m.id} className={mode === m.id ? "on" : ""} title={m.hint} onClick={() => onMode(m.id)}>{m.label}</button>
          ))}
        </div>
        <div className="segctl" data-tour="hops" role="group" aria-label="How many steps">
          {[1, 2, 3].map((h) => {
            const within = blast ? blast.nodes.filter((n) => n.hop > 0 && n.hop <= h) : [];
            const crit = within.filter((n) => n.critical).length;
            return (
              <button key={h} className={maxHop === h ? "on" : ""} onClick={() => onHop(h)}>
                {h} hop{h > 1 ? "s" : ""} <span>{within.length} reachable{crit ? `, ${crit} critical` : ""}</span>
              </button>
            );
          })}
        </div>
      </div>
      {mode !== "all" && <div className="mode-note">{mode === "granted" ? "Access this identity is entitled to." : "Access actually used in the last 30 days. The gap from “granted” is what least privilege removes."}</div>}
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
        <RingGraph data={blast} selectedNode={node} onSelectNode={onNode} maxHop={maxHop} />
        {nodeInfo && (
          <div className="inspector">
            <button className="x" onClick={() => onNode(null)} aria-label="Close">×</button>
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
              <button className="btn small block" onClick={() => onToggleCritical(nodeInfo)}>
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
        <span>rings: 1, 2 and 3 hops from the alert</span>
        <span className="shapes">● user ■ group ◆ computer</span>
      </div>
    </div>
  );
}

function IncidentTab({ incident, selectedId, onStatus, onReport }) {
  if (!incident) return <div className="tab-pane"><p className="tab-lead">This alert is not linked to any other alert.</p></div>;
  return (
    <div className="tab-pane">
      <div className="inc-head">
        <p className="tab-lead">
          <b>{incident.id}</b>: {incident.alerts.length} linked alert{incident.alerts.length > 1 ? "s" : ""}, listed by time and tagged with their attack stage
          {incident.lateral ? `. It spans ${incident.communities?.length} activity groups, a sign of lateral movement.` : "."}
        </p>
        <label className="inc-status">Status
          <select value={incident.status || "open"} onChange={(e) => onStatus(e.target.value)}>
            {INCIDENT_STATUS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      </div>
      <StageTimeline alerts={incident.alerts} selectedId={selectedId} />
      <div className="inc-actions"><button className="btn" onClick={onReport}>Open incident report</button></div>
    </div>
  );
}

function StoryTab({ incident, story, busy, onDraft, lang, onLang, languages }) {
  if (!incident) return <div className="tab-pane"><p className="tab-lead">A story is written for an incident. This alert is not linked to any other alert.</p></div>;
  return (
    <div className="tab-pane">
      <p className="tab-lead">An AI drafts the story of {incident.id} from the incident's facts only. Every sentence cites the alerts, users or machines it is based on, and a checker removes any sentence that cites something outside the incident.</p>
      <div className="story-controls">
        <label>Language
          <select value={lang} onChange={(e) => onLang(e.target.value)}>
            {languages.map((l) => <option key={l.code} value={l.code}>{l.name}</option>)}
          </select>
        </label>
        <button className="btn primary" disabled={busy} onClick={onDraft}>{busy ? "Writing…" : story ? "Draft again" : "Draft the story"}</button>
      </div>
      {story && (
        <div className="story">
          <div className="story-head">
            {story.source === "facts"
              ? "AI is not available right now, so these are the incident's facts."
              : `Drafted by AI${story.provider === "sarvam" ? " (Sarvam)" : ""}. Needs analyst approval.`}
            {story.translation_error && " Translation failed, so the story is in English."}
          </div>
          {story.sentences.map((s, i) => (
            <p key={i}>{s.text} {s.cites.map((c) => <code key={c}>{c}</code>)}
              {s.text_en && <span className="story-en">{s.text_en}</span>}
            </p>
          ))}
          {story.dropped?.length > 0 && <div className="dropped">{story.dropped.length} sentence(s) removed for citing facts outside this incident.</div>}
        </div>
      )}
    </div>
  );
}
