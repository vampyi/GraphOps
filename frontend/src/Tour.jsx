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
    text: "This is one day of security alerts from a fictional company. Somewhere in here is a real attack. GraphOps sorts the alerts so the attack comes first, and shows you why." },
  { target: "kpis", title: "The day at a glance",
    text: "How many alerts came in, how many were linked into incidents, how many sit close to a critical system and how many used a route nobody has used before." },
  { target: "strip", title: "Every alert on one timeline",
    text: "Each dot is an alert. Bigger dots scored higher. Orange dots belong to the incident you are looking at. Click any dot to open it." },
  { target: "inbox", title: "The alert inbox",
    text: "All 30 alerts, nothing deleted. The number is the GraphOps score. The thin coloured bar shows what pushed the score up. Click an alert to look at it." },
  { target: "sort", title: "Compare with today's tools",
    text: "Switch to “Severity only” to see the order most security tools use. The attack sinks far down the list. Switch back to see GraphOps' order." },
  { target: "graph", title: "Blast radius",
    text: "What an attacker could reach from this alert. The alerted machine or account is in the middle. Red shapes are critical systems, and the red dashed line is the shortest attack path. Hover a shape to light up its connections, click it for details." },
  { target: "hops", title: "1, 2 or 3 hops",
    text: "A hop is one step, like a login or a group membership. Use these buttons to see only what is 1, 2 or 3 steps away." },
  { target: "why", title: "Why it ranks here",
    text: "The score is the sum of these six graph questions plus the tool's own severity. Longer bars added more points." },
  { target: "side", title: "The incident",
    text: "Alerts that belong to the same attack, in time order and tagged with the attack stage. You can ask AI to draft the story, then mark the alert as a real attack or a false alarm." },
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
