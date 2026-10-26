import { useEffect, useRef, useState } from "react";
import { getAlerts, getLive, getScenarios, loadScenario, replayReset, replayStart } from "./api.js";
import Logo from "./Logo.jsx";
import ThemeToggle from "./Theme.jsx";
import Tour, { tourSeen } from "./Tour.jsx";
import Triage from "./Triage.jsx";
import Exposure from "./Exposure.jsx";
import Access from "./Access.jsx";
import GraphEngine from "./GraphEngine.jsx";
import Evaluation from "./Evaluation.jsx";
import Ask from "./Ask.jsx";

const VIEWS = [
  { id: "triage", label: "Triage", hint: "Rank and investigate today's alerts" },
  { id: "exposure", label: "Exposure", hint: "Attack paths and choke points before an attack" },
  { id: "access", label: "Access", hint: "Granted vs used access, the least-privilege gap" },
  { id: "graph", label: "Graph", hint: "The Neo4j engine: one query per SOC question" },
  { id: "ask", label: "Ask", hint: "Ask about today's alerts in plain words, in English or an Indian language" },
  { id: "evaluation", label: "Evaluation", hint: "Does GraphOps find the attack sooner than sorting by severity?" },
];
const POLL_MS = 2000;
const VIEW_IDS = VIEWS.map((v) => v.id);

// the view lives in the url hash (#/console/exposure), so a tab click is shareable and a refresh keeps the view
function viewFromHash() {
  const seg = (window.location.hash || "").split("/")[2];
  return VIEW_IDS.includes(seg) ? seg : "triage";
}

// CrowdStrike's 2025 median eCrime breakout time, used as the attacker's head-start budget in the guided demo
const BREAKOUT_BUDGET = 29 * 60;
const ATTACK_STEPS = [
  { tech: "T1566", label: "Phishing" },
  { tech: "T1003", label: "Credential theft" },
  { tech: "T1021", label: "Lateral movement" },
  { tech: "T1550.002", label: "Crown jewel reached" },
];

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
  const [guided, setGuided] = useState(null); // { startedAt, remaining, done, elapsedSec, incidentId }
  const [touring, setTouring] = useState(false);
  const [scenarios, setScenarios] = useState(null);
  const [error, setError] = useState(null);
  const timer = useRef(null);
  const guidedTimer = useRef(null);

  const load = () =>
    getAlerts().then(setAlerts).catch((e) => setError(`Could not reach the backend server. ${e.message}`));
  useEffect(() => { load(); }, []);
  useEffect(() => { getScenarios().then(setScenarios).catch(() => {}); }, []);

  const switchScenario = async (id) => {
    setError(null);
    try {
      await loadScenario(id);
      setScenarios((s) => (s ? { ...s, active: id } : s));
      setGuided(null); setLive((l) => ({ ...l, on: false }));
      goView("triage");
      load();
    } catch (e) { setError(`Could not load that day. ${e.message}`); }
  };
  useEffect(() => { if (!tourSeen()) setTouring(true); }, []);

  // live replay: poll /api/live, merge new or changed alerts, flag what moved
  useEffect(() => {
    if (!live.on) return;
    let seq = live.seq;
    const tick = async () => {
      try {
        const data = await getLive(seq);
        seq = data.seq;
        if (data.alerts.length) {
          setAlerts((prev) => {
            const byId = new Map(prev.map((a) => [a.id, a]));
            data.alerts.forEach((a) => byId.set(a.id, a));
            return [...byId.values()].sort((x, y) => y.score - x.score || x.time.localeCompare(y.time));
          });
          setChanged(new Set(data.alerts.map((a) => a.id)));
        }
        setLive((l) => ({ ...l, seq, replaying: data.replaying, ingested: l.ingested + data.ingested }));
      } catch (e) { setError(e.message); }
    };
    timer.current = setInterval(tick, POLL_MS);
    tick();
    return () => clearInterval(timer.current);
  }, [live.on]); // eslint-disable-line

  const startReplay = async (attack) => {
    setError(null);
    try {
      setAlerts([]); setChanged(new Set());
      await replayReset();
      await replayStart(attack, 60);
      setLive({ on: true, seq: 0, replaying: true, ingested: 0, attack });
    } catch (e) { setError(`Could not start the replay. ${e.message}`); }
  };
  const stopLive = () => { setLive((l) => ({ ...l, on: false })); load(); };

  // guided "beat the clock" demo: start the attack live, run a breakout countdown, auto-follow the attack,
  // and freeze when the attacker reaches the crown jewel (the pass-the-hash step, T1550.002).
  const startGuided = async () => {
    setError(null);
    try {
      setAlerts([]); setChanged(new Set());
      await replayReset();
      await replayStart(true, 600);
      goView("triage");
      setLive({ on: true, seq: 0, replaying: true, ingested: 0, attack: true });
      setGuided({ startedAt: Date.now(), remaining: BREAKOUT_BUDGET, done: false, elapsedSec: 0, incidentId: null });
    } catch (e) { setError(`Could not start the guided demo. ${e.message}`); }
  };
  const endGuided = () => { setGuided(null); stopLive(); };

  useEffect(() => {
    if (!guided || guided.done) return;
    guidedTimer.current = setInterval(() => {
      setGuided((g) => (g && !g.done
        ? { ...g, remaining: Math.max(0, BREAKOUT_BUDGET - Math.floor((Date.now() - g.startedAt) / 1000)) } : g));
    }, 1000);
    return () => clearInterval(guidedTimer.current);
  }, [guided?.done, guided?.startedAt]); // eslint-disable-line

  useEffect(() => {
    if (!guided || guided.done) return;
    const crown = alerts.find((a) => a.technique_id === "T1550.002");
    if (crown) {
      const elapsedSec = Math.max(1, Math.floor((Date.now() - guided.startedAt) / 1000));
      setGuided((g) => (g ? { ...g, done: true, elapsedSec, incidentId: crown.incident_id } : g));
    }
  }, [alerts]); // eslint-disable-line

  // in guided mode, keep the highest-scoring alert (the attack as it climbs) open in Triage
  const focusAlertId = guided && alerts.length ? alerts[0].id : null;

  return (
    <div className={`dash ${guided ? "has-guided" : ""}`}>
      <nav className="dnav">
        <a className="brand" href="#/"><Logo />GraphOps</a>
        <div className="views" role="tablist" data-tour="views">
          {VIEWS.map((v) => (
            <button key={v.id} role="tab" aria-selected={view === v.id} title={v.hint}
              className={view === v.id ? "on" : ""} onClick={() => goView(v.id)}>{v.label}</button>
          ))}
        </div>
        <div className="dnav-right">
          {!guided && <button className="guided-btn" onClick={startGuided} title="Replay the attack against a 29-minute breakout clock">Beat the clock</button>}
          {!guided && <LiveControls live={live} onStart={startReplay} onStop={stopLive} />}
          <button className="tour-btn" onClick={() => setTouring(true)}>Tour</button>
          <ThemeToggle />
        </div>
      </nav>
      <div className="subnav">
        <span className="tag">Synthetic data</span>
        {scenarios && scenarios.scenarios.length > 1 && (
          <label className="scenario-pick">Day
            <select value={scenarios.active} onChange={(e) => switchScenario(e.target.value)}>
              {scenarios.scenarios.map((sc) => <option key={sc.id} value={sc.id}>{sc.name}</option>)}
            </select>
          </label>
        )}
        <span className="subnav-hint">{VIEWS.find((v) => v.id === view).hint}</span>
      </div>
      {error && <div className="error" role="alert">{error} <button onClick={() => setError(null)}>dismiss</button></div>}
      {touring && <Tour onClose={() => setTouring(false)} />}

      {view === "triage" && <Triage alerts={alerts} changed={changed} live={live} focusAlertId={focusAlertId} onReload={load} onError={setError} />}
      {view === "exposure" && <Exposure onError={setError} />}
      {view === "access" && <Access onError={setError} />}
      {view === "graph" && <GraphEngine onError={setError} />}
      {view === "ask" && <Ask />}
      {view === "evaluation" && <Evaluation onError={setError} dayName={scenarios?.scenarios.find((sc) => sc.id === scenarios.active)?.name} />}

      {guided && <GuidedBanner guided={guided} alerts={alerts} onClose={endGuided} />}
    </div>
  );
}

function LiveControls({ live, onStart, onStop }) {
  if (live.on) {
    return (
      <div className="live-controls on" data-tour="live">
        <span className={`live-dot ${live.replaying ? "pulse" : "done"}`} />
        <span className="live-label">
          {live.replaying ? "Replaying live" : "Replay finished"} · {live.ingested} events
        </span>
        <button onClick={onStop}>Stop</button>
      </div>
    );
  }
  return (
    <div className="live-controls" data-tour="live">
      <button className="primary" onClick={() => onStart(true)} title="Stream the day with the attack mixed in">Replay attack live</button>
      <button onClick={() => onStart(false)} title="Stream a normal day, no attack">Normal day</button>
    </div>
  );
}

function fmt(s) {
  const m = Math.floor(s / 60), ss = s % 60;
  return `${m}:${String(ss).padStart(2, "0")}`;
}

// the "beat the clock" overlay: a breakout countdown, the kill chain lighting up as each step lands, and a
// result card the moment the attacker reaches the crown jewel.
function GuidedBanner({ guided, alerts, onClose }) {
  const seen = new Set(alerts.map((a) => a.technique_id));
  const reached = ATTACK_STEPS.findIndex((s) => !seen.has(s.tech));
  const doneSteps = reached === -1 ? ATTACK_STEPS.length : reached;
  const spare = BREAKOUT_BUDGET - guided.elapsedSec;

  return (
    <div className={`guided ${guided.done ? "done" : ""}`} role="status">
      <div className="guided-clock">
        <div className="guided-clock-v">{fmt(guided.done ? spare : guided.remaining)}</div>
        <div className="guided-clock-l">{guided.done ? "left of the 29:00 budget" : "attacker breakout budget"}</div>
      </div>
      <div className="guided-mid">
        <div className="guided-chain">
          {ATTACK_STEPS.map((s, i) => (
            <span key={s.tech} className={`gchain ${i < doneSteps ? "hit" : ""} ${i === doneSteps && !guided.done ? "next" : ""}`}>
              <i />{s.label}
            </span>
          ))}
        </div>
        {guided.done
          ? <div className="guided-result">GraphOps connected the full attack chain in <b>{guided.elapsedSec}s</b>. The attacker's 29-minute head start is still on the clock, so you have the whole budget to contain it. Reading these as separate alerts, an analyst reconstructs this by hand.</div>
          : <div className="guided-status">Watching the attack unfold live. GraphOps links each step into one incident as it lands.</div>}
      </div>
      <button className="guided-close" onClick={onClose}>{guided.done ? "Done" : "Stop"}</button>
    </div>
  );
}
