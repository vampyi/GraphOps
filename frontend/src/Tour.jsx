import { useEffect, useLayoutEffect, useState } from "react";

const KEY = "graphops-tour-seen";

// the tour shows once per browser. storage can be blocked (private windows), so every access is guarded.
export function tourSeen() {
  try { return localStorage.getItem(KEY) === "1"; } catch { return true; }
}
function markSeen() {
  try { localStorage.setItem(KEY, "1"); } catch { /* storage unavailable, nothing to remember */ }
}

const STEPS = [
  { target: null, title: "Welcome to GraphOps",
    text: "This is one day of security alerts from a fictional company, with a scripted, synthetic attack hidden inside the noise. GraphOps sorts the alerts so the attack comes first, and shows you why." },
  { target: "views", title: "Three views",
    text: "Triage ranks today's alerts. Exposure maps the attack paths and choke points that exist before any attack. Access compares the access people are granted with the access they actually use." },
  { target: "live", title: "Watch it happen live",
    text: "Replay the day as a live stream through Kafka. Alerts arrive one by one, and you can see the attack climb the inbox in real time." },
  { target: "kpis", title: "The day at a glance",
    text: "How many alerts came in, how many were linked into incidents, how many sit close to a critical system and how many used a route nobody has used before." },
  { target: "strip", title: "Every alert on one timeline",
    text: "Each dot is an alert. Bigger dots scored higher. Orange dots belong to the incident you are looking at. Click any dot to open it." },
  { target: "inbox", title: "The alert inbox",
    text: "Every alert, nothing deleted. The number is the GraphOps score. The thin coloured bar shows what pushed it up. Switch to “Severity only” to see the order most tools use: the attack sinks far down." },
  { target: "modes", title: "Granted vs used",
    text: "Draw the blast radius over all attack routes, over only granted permissions, or over only the routes actually used. The gap between granted and used is the risk least privilege removes." },
  { target: "graph", title: "Blast radius",
    text: "What an attacker could reach from this alert. The alerted machine or account is in the middle. Red shapes are critical systems, and the red dashed line is the shortest attack path. Click any shape for details, or to mark it critical." },
  { target: "hops", title: "1, 2 or 3 hops",
    text: "A hop is one step, like a login or a group membership. Use these buttons to see only what is 1, 2 or 3 steps away." },
  { target: "why", title: "Why it ranks here",
    text: "The score is the sum of six graph questions plus the tool's own severity. Longer bars added more points." },
  { target: "side", title: "The incident",
    text: "Alerts that belong to the same attack, in time order and tagged with the attack stage. Draft the story with AI, open a containment report, set the incident's status, and mark each alert real, benign or a false alarm." },
];

export default function Tour({ onClose }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState(null);
  const step = STEPS[i];

  useLayoutEffect(() => {
    if (!step.target) { setRect(null); return; }
    const el = document.querySelector(`[data-tour="${step.target}"]`);
    if (!el) { setRect(null); return; }
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    const measure = () => setRect(el.getBoundingClientRect());
    // keep measuring while the smooth scroll settles
    let frames = 0, raf;
    const loop = () => { measure(); if (frames++ < 60) raf = requestAnimationFrame(loop); };
    loop();
    const t = setTimeout(measure, 900);
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", measure, true);
    return () => { cancelAnimationFrame(raf); clearTimeout(t); window.removeEventListener("resize", measure); window.removeEventListener("scroll", measure, true); };
  }, [i]); // eslint-disable-line

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") finish();
      if (e.key === "ArrowRight") next();
      if (e.key === "ArrowLeft") setI((x) => Math.max(0, x - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const finish = () => { markSeen(); onClose(); };
  const next = () => (i < STEPS.length - 1 ? setI(i + 1) : finish());

  const pad = 8;
  const card = { width: 340 };
  if (rect) {
    const below = rect.bottom + 14 + 200 < window.innerHeight;
    card.top = below ? rect.bottom + pad + 10 : Math.max(12, rect.top - pad - 10 - 200);
    card.left = Math.min(Math.max(12, rect.left), window.innerWidth - card.width - 12);
  } else {
    card.top = window.innerHeight / 2 - 110;
    card.left = window.innerWidth / 2 - card.width / 2;
  }

  return (
    <div className="tour" role="dialog" aria-label="GraphOps tour">
      {rect ? (
        <div className="tour-hole" style={{ top: rect.top - pad, left: rect.left - pad, width: rect.width + pad * 2, height: rect.height + pad * 2 }} />
      ) : (
        <div className="tour-dim" />
      )}
      <div className="tour-card" style={card}>
        <div className="tour-count">{i + 1} of {STEPS.length}</div>
        <h4>{step.title}</h4>
        <p>{step.text}</p>
        <div className="tour-actions">
          <button className="link" onClick={finish}>Skip tour</button>
          <div>
            {i > 0 && <button onClick={() => setI(i - 1)}>Back</button>}
            <button className="primary" onClick={next}>{i < STEPS.length - 1 ? "Next" : "Start exploring"}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
