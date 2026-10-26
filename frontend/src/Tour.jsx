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
  { target: null, title: "GraphOps",
    text: "One day of alerts at a fictional company, with a scripted attack hidden in the noise. GraphOps ranks the attack first and shows why." },
  { target: "views", title: "Views",
    text: "Triage ranks alerts. Exposure maps attack paths before an attack. Access shows unused permissions. Ask answers questions. Evaluation measures the ranking." },
  { target: "live", title: "Live replay",
    text: "Stream the day through Kafka and watch alerts arrive and re-rank." },
  { target: "kpis", title: "The day at a glance", text: "Alerts, incidents, alerts near critical assets, new routes, and what is still unreviewed." },
  { target: "filters", title: "Filters", text: "Search, or filter by severity, verdict, or what the graph found." },
  { target: "inbox", title: "Ranked inbox",
    text: "Highest GraphOps score first. Nothing is deleted. Switch to Severity to see the usual order: the attack sinks." },
  { target: "tabs", tab: "why", title: "Alert details", text: "Record a verdict, then read the tabs left to right." },
  { target: "why", tab: "why", title: "Why it ranks", text: "Points each graph question added to the score." },
  { target: "graph", tab: "blast", title: "Blast radius",
    text: "What an attacker could reach from this alert. Red is critical; the dashed line is the shortest attack path. Click a shape for details." },
  { target: "modes", tab: "blast", title: "Granted vs used", text: "Follow every route, only permissions held, or only routes used. The gap is what least privilege removes." },
  { target: "hops", tab: "blast", title: "Hops", text: "Show what is 1, 2 or 3 steps away." },
  { target: "tabs", tab: "incident", title: "Incident", text: "The linked alerts in time order, with attack stages, status and a report. Story drafts a cited summary." },
];

export default function Tour({ onClose }) {
  const [i, setI] = useState(0);
  const [rect, setRect] = useState(null);
  const [retries, setRetries] = useState(0);
  const step = STEPS[i];

  useLayoutEffect(() => {
    if (step.tab) window.dispatchEvent(new CustomEvent("graphops:tab", { detail: step.tab }));
    if (!step.target) { setRect(null); return; }
    let el = document.querySelector(`[data-tour="${step.target}"]`);
    if (!el && step.tab && retries < 10) {
      // the tab's content renders on the next frame; measure once it exists
      const retry = setTimeout(() => setRetries((n) => n + 1), 60);
      setRect(null);
      return () => clearTimeout(retry);
    }
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
  }, [i, retries]); // eslint-disable-line

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") finish();
      if (e.key === "ArrowRight") next();
      if (e.key === "ArrowLeft") go(Math.max(0, i - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const finish = () => { markSeen(); onClose(); };
  const go = (n) => { setRetries(0); setI(n); };
  const next = () => (i < STEPS.length - 1 ? go(i + 1) : finish());

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
            {i > 0 && <button onClick={() => go(i - 1)}>Back</button>}
            <button className="primary" onClick={next}>{i < STEPS.length - 1 ? "Next" : "Start exploring"}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
