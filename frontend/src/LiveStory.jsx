import { useEffect, useRef, useState } from "react";

// the landing page's four-beat story, played on a loop once it scrolls into view: alerts arrive sorted by severity,
// they land on the graph, the attack path lights up, and the list re-ranks by graph position. the alerts, scores
// and machines are the demo company's tuning day, as the console shows them.
const ALERTS = [
  { id: "n1", name: "Drive-by download blocked", on: "laptop-s1", sev: "Critical", score: 30 },
  { id: "n2", name: "Adware bundle detected", on: "laptop-s2", sev: "High", score: 29 },
  { id: "n3", name: "Known bad IP blocked", on: "laptop-s1", sev: "High", score: 29 },
  { id: "a1", name: "Phishing link clicked", on: "laptop-42", sev: "Medium", score: 60, attack: true },
  { id: "a2", name: "Credential dumping from LSASS", on: "laptop-42", sev: "Medium", score: 60, attack: true },
  { id: "a4", name: "Pass-the-hash authentication", on: "customer-db", sev: "Medium", score: 63, attack: true },
  { id: "a3", name: "Remote logon from an unusual host", on: "server-7", sev: "Low", score: 85, attack: true },
];
const BY_GRAPH = [...ALERTS].sort((x, y) => y.score - x.score).map((a) => a.id);

const NODES = {
  "laptop-42": { x: 92, y: 212, label: "laptop-42" },
  "server-7": { x: 262, y: 128, label: "server-7" },
  "customer-db": { x: 448, y: 92, label: "customer-db", critical: true },
  "dc-01": { x: 448, y: 282, label: "dc-01", critical: true },
  "g_helpdesk": { x: 282, y: 250, label: "g_helpdesk", group: true },
  "laptop-s1": { x: 120, y: 352, label: "laptop-s1" },
  "laptop-s2": { x: 300, y: 362, label: "laptop-s2" },
  "print-01": { x: 70, y: 80, label: "print-01" },
};
const EDGES = [["print-01", "laptop-42"], ["laptop-42", "g_helpdesk"], ["g_helpdesk", "dc-01"], ["laptop-s1", "g_helpdesk"],
  ["laptop-s2", "laptop-s1"], ["laptop-s2", "g_helpdesk"], ["server-7", "g_helpdesk"], ["laptop-42", "server-7"],
  ["server-7", "customer-db"]];
const PATH = ["laptop-42", "server-7", "customer-db"];

const BEATS = [
  { title: "Alerts arrive", text: "Sorted by the tools' own severity, the noise sits on top." },
  { title: "Placed on the graph", text: "Each alert lands on the machine it came from." },
  { title: "The path lights up", text: "Four alerts sit on one route to the customer database." },
  { title: "Ranked by the graph", text: "The attack moves to the top. Nothing is deleted." },
];
const BEAT_MS = 3400;
const ROW = 46;

export default function LiveStory() {
  const box = useRef(null);
  const [beat, setBeat] = useState(0);
  const [running, setRunning] = useState(false);

  // start when visible, pause when scrolled away; reduced motion shows the last beat, still
  useEffect(() => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) { setBeat(3); return; }
    const io = new IntersectionObserver(([en]) => setRunning(en.isIntersecting), { threshold: 0.35 });
    if (box.current) io.observe(box.current);
    return () => io.disconnect();
  }, []);
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setBeat((b) => (b + 1) % BEATS.length), BEAT_MS);
    return () => clearInterval(t);
  }, [running]);

  const order = beat === 3 ? BY_GRAPH : ALERTS.map((a) => a.id);
  const placed = beat >= 1;
  const lit = beat >= 2;

  return (
    <div className="ls" ref={box} data-beat={beat}>
      <ol className="ls-beats">
        {BEATS.map((b, i) => (
          <li key={b.title} className={i === beat ? "on" : i < beat ? "done" : ""}>
            <button type="button" onClick={() => { setBeat(i); setRunning(false); }}>
              <span className="lp-mono">{String(i + 1).padStart(2, "0")}</span>
              <b>{b.title}</b>
              <small>{b.text}</small>
              <i style={{ animationDuration: `${BEAT_MS}ms` }} />
            </button>
          </li>
        ))}
      </ol>

      <div className="ls-stage">
        <div className="ls-list" style={{ height: ALERTS.length * ROW }}>
          <p className="ls-cap lp-mono">{beat === 3 ? "GraphOps score" : "Severity"}</p>
          {ALERTS.map((a) => {
            const i = order.indexOf(a.id);
            return (
              <div key={a.id} className={`ls-row ${a.attack && lit ? "atk" : ""}`} style={{ transform: `translateY(${i * ROW}px)` }}>
                <span className="ls-rank">#{i + 1}</span>
                <span className="ls-name">{a.name}<small>{a.on}</small></span>
                <span className={`ls-val ${beat === 3 ? "score" : `sev-${a.sev.toLowerCase()}`}`}>{beat === 3 ? a.score : a.sev}</span>
              </div>
            );
          })}
        </div>

        <svg className="ls-graph" viewBox="0 0 540 420" role="img"
          aria-label="A small company graph: four alerts sit on the route from laptop-42 through server-7 to the customer database">
          {EDGES.map(([s, d]) => {
            const onPath = PATH.indexOf(s) >= 0 && PATH.indexOf(d) === PATH.indexOf(s) + 1;
            return <line key={s + d} className={`ls-edge ${onPath && lit ? "path" : ""} ${placed ? "in" : ""}`}
              x1={NODES[s].x} y1={NODES[s].y} x2={NODES[d].x} y2={NODES[d].y} />;
          })}
          {Object.entries(NODES).map(([id, n], k) => (
            <g key={id} className={`ls-node ${n.critical ? "crit" : ""} ${placed ? "in" : ""} ${lit && PATH.includes(id) ? "lit" : ""}`}
              style={{ transitionDelay: `${k * 50}ms` }} transform={`translate(${n.x} ${n.y})`}>
              {n.critical && <circle className="ls-halo" r="26" />}
              {n.group ? <rect x="-11" y="-11" width="22" height="22" rx="5" /> : <circle r={n.critical ? 13 : 10} />}
              <text y={n.critical ? 32 : 28}>{n.label}</text>
            </g>
          ))}
          {ALERTS.map((a, k) => {
            const n = NODES[a.on];
            const same = ALERTS.filter((b) => b.on === a.on);
            const dx = (same.indexOf(a) - (same.length - 1) / 2) * 16;
            return <circle key={a.id} className={`ls-pin ${a.attack ? "atk" : ""} ${placed ? "in" : ""} ${lit && a.attack ? "lit" : ""}`}
              style={{ transitionDelay: `${200 + k * 70}ms` }} cx={n.x + dx} cy={n.y - 22} r="6.5" />;
          })}
        </svg>
      </div>
    </div>
  );
}
