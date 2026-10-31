import { useEffect, useRef, useState } from "react";
import { getAlerts, getLive, getScenarios, loadScenario, replayReset, replayStart } from "./api.js";
import Logo from "./Logo.jsx";
import { Info } from "./parts.jsx";
import ThemeToggle from "./Theme.jsx";
import Tour, { tourSeen } from "./Tour.jsx";
import Triage from "./Triage.jsx";
import Access from "./Access.jsx";
import GraphEngine from "./GraphEngine.jsx";
import Ask from "./Ask.jsx";
import AttackPaths from "./AttackPaths.jsx";
import Agents from "./Agents.jsx";

const VIEWS = [
  { id: "triage", label: "Triage", hint: "Ranked alerts and their details" },
  { id: "paths", label: "Attack paths", hint: "Routes to critical assets before any attack, and what one system can reach" },
  { id: "access", label: "Access", hint: "Granted vs used access" },
  { id: "agents", label: "AI agents", hint: "A real AI agent: its access and live activity" },
  { id: "graph", label: "Graph", hint: "The Neo4j graph, its algorithms and the proof that the ranking works" },
  { id: "ask", label: "Ask", hint: "Questions in plain language" },
];
const POLL_MS = 2000;
const REAL_POLL_MS = 4000; // real data: laptops report once a minute, agents on every action
const VIEW_IDS = VIEWS.map((v) => v.id);

// the view lives in the url hash (#/console/exposure), so a tab click is shareable and a refresh keeps the view
function viewFromHash() {
  const seg = (window.location.hash || "").split("/")[2];
  if (seg === "exposure" || seg === "explore") return "paths";
  if (seg === "evaluation") return "graph";
  return VIEW_IDS.includes(seg) ? seg : "triage";
}

export default function Dashboard() {
  const [view, setView] = useState(viewFromHash);
  const goView = (id) => { window.location.hash = id === "triage" ? "#/console" : `#/console/${id}`; setView(id); };
  useEffect(() => {
    const sync = () => setView(viewFromHash());
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  const [alerts, setAlerts] = useState([]);
  const [changed, setChanged] = useState(new Set());
  const [live, setLive] = useState({ on: false, seq: 0, replaying: false, ingested: 0, attack: true });
  const [touring, setTouring] = useState(false);
  const [scenarios, setScenarios] = useState(null);
  const [switching, setSwitching] = useState(false);
  const switchingRef = useRef(false);
  const [dataVersion, setDataVersion] = useState(0); // bumped after a scenario loads, so every tab refetches
  const [error, setError] = useState(null);
  const timer = useRef(null);
  const sending = useRef(false); // true while the replay request is still sending the day (it can take minutes on vercel)

  const load = () =>
    getAlerts().then(setAlerts).catch((e) => setError(`Could not reach the backend server. ${e.message}`));
  useEffect(() => { load(); }, []);
  useEffect(() => { getScenarios().then(setScenarios).catch(() => {}); }, []);
  // the hosted demo has one shared database: follow a day another visitor loaded, and say when it is mid-reload
  const [busy, setBusy] = useState(null);
  useEffect(() => {
    const t = setInterval(() => {
      if (switchingRef.current || live.on) return;
      getScenarios().then((s) => {
        setBusy(s.busy);
        setScenarios((cur) => {
          if (cur && !s.busy && s.active !== cur.active) { load(); setDataVersion((v) => v + 1); }
          return s;
        });
      }).catch(() => {});
    }, 15000);
    return () => clearInterval(t);
  }, [live.on]); // eslint-disable-line

  // show the chosen scenario straight away, keep the analyst on the tab they are on, and redraw it once the
  // server has rebuilt the graph for that day
  const switchScenario = async (id) => {
    const before = scenarios?.active;
    setError(null);
    setSwitching(true);
    switchingRef.current = true;
    setScenarios((s) => (s ? { ...s, active: id } : s));
    // a running stream keeps writing to the database: stop it first, so it never collides with the reload
    clearTimeout(timer.current);
    setLive((l) => ({ ...l, on: false }));
    try {
      await loadScenario(id);
      await load(); // the new day's alerts must be in place before the tabs redraw, or triage opens a stale alert
      setDataVersion((v) => v + 1);
    } catch (e) {
      setScenarios((s) => (s ? { ...s, active: before } : s));
      setError(e.message.startsWith("409") ? "Someone else is reloading the demo data. Try again in a minute."
        : `Could not load that scenario. ${e.message}`);
    }
    setSwitching(false);
    switchingRef.current = false;
  };
  useEffect(() => { if (!tourSeen()) setTouring(true); }, []);

  // live replay: poll /api/live, merge new or changed alerts, flag what moved
  useEffect(() => {
    if (!live.on || !live.real) return;
    let stopped = false;
    let known = new Set(alerts.map((a) => a.id));
    const tick = async () => {
      try {
        const next = await getAlerts();
        if (stopped) return;
        const fresh = next.filter((a) => !known.has(a.id)).map((a) => a.id);
        known = new Set(next.map((a) => a.id));
        setAlerts(next);
        if (fresh.length) setChanged(new Set(fresh));
        setLive((l) => ({ ...l, ingested: l.ingested + fresh.length }));
      } catch (e) { if (!stopped) setError(e.message); }
      if (!stopped) timer.current = setTimeout(tick, REAL_POLL_MS);
    };
    tick();
    return () => { stopped = true; clearTimeout(timer.current); };
  }, [live.on, live.real]); // eslint-disable-line

  useEffect(() => {
    if (!live.on || live.real) return;
    let seq = live.seq;
    let stopped = false;
    // ask again only after the previous answer arrives, so slow answers never pile up
    const tick = async () => {
      try {
        const data = await getLive(seq);
        if (stopped) return;
        seq = data.seq;
        if (data.alerts.length) {
          setAlerts((prev) => {
            const byId = new Map(prev.map((a) => [a.id, a]));
            data.alerts.forEach((a) => byId.set(a.id, a));
            return [...byId.values()].sort((x, y) => y.score - x.score || x.time.localeCompare(y.time));
          });
          setChanged(new Set(data.alerts.map((a) => a.id)));
        }
        setLive((l) => ({ ...l, seq, replaying: sending.current || data.replaying, ingested: l.ingested + data.ingested }));
      } catch (e) { if (!stopped) setError(e.message); }
      if (!stopped) timer.current = setTimeout(tick, POLL_MS);
    };
    tick();
    return () => { stopped = true; clearTimeout(timer.current); };
  }, [live.on]); // eslint-disable-line

  const startReplay = async (attack) => {
    setError(null);
    if (scenarios?.active === "real_data") {
      setLive({ on: true, real: true, seq: 0, replaying: false, ingested: 0, attack });
      return;
    }
    try {
      setAlerts([]); setChanged(new Set());
      await replayReset(scenarios?.active);
      send(attack, 60);
      setLive({ on: true, seq: 0, replaying: true, ingested: 0, attack });
    } catch (e) {
      setError(e.message.startsWith("409") ? "Someone else is reloading the demo data. Try again in a minute."
        : `Could not start the replay. ${e.message}`);
    }
  };
  // start sending the day without waiting for it to finish; alerts appear through polling as they land
  const send = (attack, speed) => {
    sending.current = true;
    replayStart(attack, speed, scenarios?.active)
      .catch((e) => setError(`The replay stopped early. ${e.message}`))
      .finally(() => { sending.current = false; });
  };
  const stopLive = () => { setLive((l) => ({ ...l, on: false })); load(); };

  return (
    <div className="dash">
      <nav className="dnav">
        <a className="brand" href="#/"><Logo />GraphOps</a>
        <div className="views" role="tablist" data-tour="views">
          {VIEWS.map((v) => (
            <button key={v.id} role="tab" aria-selected={view === v.id} title={v.hint}
              className={view === v.id ? "on" : ""} onClick={() => goView(v.id)}>{v.label}</button>
          ))}
        </div>
        <div className="dnav-right">
          <LiveControls live={live} onStart={() => startReplay(true)} onStop={stopLive} />
          <button className="tour-btn" onClick={() => setTouring(true)}>Help</button>
          <ThemeToggle />
        </div>
      </nav>
      <div className="subnav">
        {(() => {
          const real = scenarios?.scenarios.find((sc) => sc.id === scenarios.active)?.real;
          if (scenarios?.active === "real_data")
            return <span className="tag real" title="Only what team laptops and Claude Code agents report, live">Real data <em>live laptops & AI agents only</em></span>;
          return <span className={`tag ${real ? "real" : ""}`} title="Team laptops and AI agents report live on top of every day">
            {real ? "Real lab logs" : "Synthetic company"} <em>+ live laptops & AI agents</em></span>;
        })()}
        {scenarios && scenarios.scenarios.length > 1 && (
          <label className="scenario-pick">Scenario
            <select value={scenarios.active} disabled={switching} onChange={(e) => switchScenario(e.target.value)}>
              {scenarios.scenarios.map((sc) => <option key={sc.id} value={sc.id}>{sc.name}</option>)}
            </select>
          </label>
        )}
        {switching && <span className="subnav-hint loading">Loading scenario…</span>}
        {!switching && busy && <span className="subnav-hint loading">Another visitor is reloading the demo data…</span>}
        <span className="subnav-hint">{VIEWS.find((v) => v.id === view).hint}</span>
      </div>
      {error && <div className="error" role="alert">{error} <button onClick={() => setError(null)}>dismiss</button></div>}
      {touring && <Tour onClose={() => setTouring(false)} />}

      {view === "triage" && <Triage key={dataVersion} alerts={alerts} changed={changed} live={live} onReload={load} onError={setError} />}
      {view === "paths" && <AttackPaths key={dataVersion} onError={setError} />}
      {view === "access" && <Access key={dataVersion} onError={setError} />}
      {view === "agents" && <Agents key={dataVersion} onError={setError} />}
      {view === "graph" && <GraphEngine key={dataVersion} onError={setError} />}
      {view === "ask" && <Ask />}

    </div>
  );
}

function LiveControls({ live, onStart, onStop }) {
  if (live.on) {
    return (
      <div className="live-controls on" data-tour="live">
        <span className={`live-dot ${live.replaying || live.real ? "pulse" : "done"}`} />
        <span className="live-label">{live.real ? `Live · ${live.ingested} new from laptops & agents`
          : `${live.replaying ? "Live" : "Stream complete"} · ${live.ingested} events`}</span>
        <button onClick={onStop}>Stop</button>
      </div>
    );
  }
  return (
    <div className="live-controls" data-tour="live">
      <button onClick={onStart}><span className="live-dot" />Stream live</button>
      <Info align="right" text="Replays the selected scenario's telemetry through Kafka as if it were happening now. Alerts are scored and linked as they arrive." />
    </div>
  );
}
