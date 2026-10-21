import { useEffect, useRef, useState } from "react";
import { getAlerts, getLive, replayReset, replayStart } from "./api.js";
import Logo from "./Logo.jsx";
import ThemeToggle from "./Theme.jsx";
import Tour, { tourSeen } from "./Tour.jsx";
import Triage from "./Triage.jsx";
import Exposure from "./Exposure.jsx";
import Access from "./Access.jsx";

const VIEWS = [
  { id: "triage", label: "Triage", hint: "Rank and investigate today's alerts" },
  { id: "exposure", label: "Exposure", hint: "Attack paths and choke points before an attack" },
  { id: "access", label: "Access", hint: "Granted vs used access, the least-privilege gap" },
];
const POLL_MS = 2000;

export default function Dashboard() {
  const [view, setView] = useState("triage");
  const [alerts, setAlerts] = useState([]);
  const [changed, setChanged] = useState(new Set());
  const [live, setLive] = useState({ on: false, seq: 0, replaying: false, ingested: 0, attack: true });
  const [touring, setTouring] = useState(false);
  const [error, setError] = useState(null);
  const timer = useRef(null);

  const load = () =>
    getAlerts().then(setAlerts).catch((e) => setError(`Could not reach the backend server. ${e.message}`));
  useEffect(() => { load(); }, []);
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

  return (
    <div className="dash">
      <nav className="dnav">
        <a className="brand" href="#/"><Logo />GraphOps</a>
        <div className="views" role="tablist" data-tour="views">
          {VIEWS.map((v) => (
            <button key={v.id} role="tab" aria-selected={view === v.id} title={v.hint}
              className={view === v.id ? "on" : ""} onClick={() => setView(v.id)}>{v.label}</button>
          ))}
        </div>
        <div className="dnav-right">
          <LiveControls live={live} onStart={startReplay} onStop={stopLive} />
          <button className="tour-btn" onClick={() => setTouring(true)}>Tour</button>
          <ThemeToggle />
        </div>
      </nav>
      <div className="subnav">
        <span className="tag">Sample organisation · synthetic data</span>
        <span className="subnav-hint">{VIEWS.find((v) => v.id === view).hint}</span>
      </div>
      {error && <div className="error" role="alert">{error} <button onClick={() => setError(null)}>dismiss</button></div>}
      {touring && <Tour onClose={() => setTouring(false)} />}

      {view === "triage" && <Triage alerts={alerts} changed={changed} live={live} onReload={load} onError={setError} />}
      {view === "exposure" && <Exposure onError={setError} />}
      {view === "access" && <Access onError={setError} />}
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
