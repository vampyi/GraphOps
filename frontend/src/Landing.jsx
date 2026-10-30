import { useEffect, useRef, useState } from "react";
import Logo from "./Logo.jsx";
import ThemeToggle from "./Theme.jsx";
import StippleOrb from "./StippleOrb.jsx";

const STATS = [
  { value: "73%", label: "of SANS 2025 survey respondents cited false positives as a main detection challenge", source: "SANS Institute" },
  { value: "29 min", label: "average time for an attacker to start spreading inside a network in 2025", source: "CrowdStrike" },
  { value: "₹25.5 cr", label: "average cost of a data breach in India in 2026, a record high", source: "IBM" },
  { value: "6 hours", label: "to report a cyber incident to CERT-In after noticing it", source: "CERT-In" },
];

const PAINS = [
  { title: "Too many alarms", status: "live", problem: "Most alerts are false, so the real attack hides in the noise.", fix: "Ranks every alert by where it sits on the attacker's map. Nothing is deleted." },
  { title: "Alerts don't connect", status: "live", problem: "One attack shows up as many separate alerts.", fix: "Links alerts along the path the attacker took and tags each with its attack stage." },
  { title: "Attackers are faster", status: "live", problem: "Attackers spread in minutes while analysts take hours.", fix: "Works out each machine's distance to critical assets ahead of time, so scoring is instant." },
  { title: "How bad is this?", status: "live", problem: "Nobody can quickly see what a hacked machine can reach.", fix: "Draws the 1, 2 and 3 hop blast radius around any alert." },
  { title: "Hidden danger", status: "live", problem: "Risky access paths exist long before anyone uses them.", fix: "Maps attack paths and choke points before any attack, and shows which few fixes cut the most paths." },
  { title: "Too much access", status: "live", problem: "People hold far more access than they use.", fix: "Compares the access each identity is granted with the access it actually uses." },
  { title: "One step at a time", status: "live", problem: "Each step can look normal while the whole route is strange.", fix: "Scores an alert higher when a logon route next to it was used for the first time." },
];

const STEPS = [
  { n: "01", title: "Collect", text: "Logins, permissions, machines and alerts stream in from a company's existing tools." },
  { n: "02", title: "Connect", text: "Everything becomes one Neo4j graph: users, machines and groups as dots, logins and permissions as lines." },
  { n: "03", title: "Rank", text: "Each alert is scored on six graph questions and linked to the alerts on the same attack path." },
  { n: "04", title: "Explain", text: "The analyst sees the blast radius, the attack step by step and a cited incident story, in English or an Indian language." },
];

const WINS = [
  { tint: "mint", title: "Built on the graph", text: "Attack paths, blast radius, choke points and unused access are all graph queries on Neo4j." },
  { tint: "cream", title: "Granted vs used", text: "Each identity's blast radius is drawn twice: over the access it holds and the access it uses. The gap is the risk least privilege removes." },
  { tint: "sky", title: "Ask in plain language", text: "Questions are answered from GraphOps' own lookups, every sentence cited, in English or ten Indian languages, with Sarvam AI." },
  { tint: "mint", title: "Measured", text: "On five held-out attack days, GraphOps ranked the attack above severity sorting every time. Every number is published." },
];

const NAV = [
  { label: "Problem", href: "problem" },
  { label: "How it works", href: "how" },
  { label: "What sets it apart", href: "wins" },
];

function Arrow() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 8h9.5M8.5 4l4 4-4 4" />
    </svg>
  );
}

const jump = (id) => (e) => {
  e.preventDefault();
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
};

// the orb has to paint itself in the colours of whichever theme is on, and the
// theme lives as a data attribute on <html>, so watch that rather than duplicate state
function useTheme() {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "dark");
  useEffect(() => {
    const el = document.documentElement;
    const mo = new MutationObserver(() => setTheme(el.dataset.theme || "dark"));
    mo.observe(el, { attributes: true, attributeFilter: ["data-theme"] });
    return () => mo.disconnect();
  }, []);
  return theme;
}

export default function Landing() {
  const theme = useTheme();
  const [stuck, setStuck] = useState(false);
  const root = useRef(null);

  useEffect(() => {
    const onScroll = () => setStuck(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // sections fade up once as they come into view, then stay put
  useEffect(() => {
    const targets = root.current?.querySelectorAll("[data-reveal]");
    if (!targets?.length) return;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      targets.forEach((t) => t.setAttribute("data-in", ""));
      return;
    }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return;
        en.target.setAttribute("data-in", "");
        io.unobserve(en.target);
      });
    }, { rootMargin: "0px 0px -12% 0px", threshold: 0.08 });
    targets.forEach((t) => io.observe(t));
    return () => io.disconnect();
  }, []);

  const dark = theme !== "light";

  return (
    <div className="lp-root" ref={root}>
      <a className="lp-skip" href="#lp-main">Skip to content</a>

      <nav className="lp-nav" data-stuck={stuck || undefined}>
        <div className="lp-wrap">
          <a className="lp-brand" href="#/"><Logo />GraphOps</a>
          <div className="lp-links">
            {NAV.map((n) => <a key={n.href} href={`#${n.href}`} onClick={jump(n.href)}>{n.label}</a>)}
          </div>
          <div className="lp-navr">
            <ThemeToggle />
            <a className="lp-btn lp-btn-sm" href="#/console">Open the console<Arrow /></a>
          </div>
        </div>
      </nav>

      <main id="lp-main">
        <header className="lp-hero">
          <div className="lp-wrap lp-hero-grid">
            <div className="lp-hero-copy">
              <p className="lp-mono">Graph analytics for threat hunting</p>
              <h1 className="lp-h1">
                <span>Defenders think in lists.</span>
                <span className="lp-accent">Attackers think in graphs.</span>
              </h1>
              <p className="lp-attrib">John Lambert, Microsoft</p>
              <p className="lp-lead">
                GraphOps ranks every security alert by where it sits on the attacker's map, links scattered alerts
                into one incident and shows what an attacker can reach next.
              </p>
              <div className="lp-cta">
                <a className="lp-btn" href="#/console">Open the console<Arrow /></a>
                <a className="lp-link" href="#how" onClick={jump("how")}>See how it works<Arrow /></a>
              </div>
            </div>
            <StippleOrb
              dark={dark}
              accent={dark ? "#2dd4bf" : "#0b8176"}
              critical={dark ? "#f87171" : "#dc2626"}
            />
          </div>

          <div className="lp-wrap lp-trust">
            <span className="lp-mono">Built for</span>
            <ul>
              <li>hackFront India 2026</li>
              <li>Cybersecurity theme</li>
              <li>Team Pingu Haters</li>
            </ul>
          </div>
        </header>

        <section className="lp-sec lp-statsec" data-reveal>
          <div className="lp-wrap">
            <ul className="lp-stats">
              {STATS.map((s) => (
                <li key={s.value}>
                  <b>{s.value}</b>
                  <p>{s.label}</p>
                  <small>{s.source}</small>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="lp-sec lp-pad" id="problem" data-reveal>
          <div className="lp-wrap">
            <p className="lp-mono">The seven pain points</p>
            <h2 className="lp-h2">Why attacks get missed</h2>
            <ol className="lp-pains">
              {PAINS.map((p, i) => (
                <li key={p.title}>
                  <span className="lp-num">{String(i + 1).padStart(2, "0")}</span>
                  <div>
                    <h3>{p.title}</h3>
                    <p className="lp-prob">{p.problem}</p>
                    <p className="lp-fix">{p.fix}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="lp-sec lp-pad" id="how" data-reveal>
          <div className="lp-wrap">
            <p className="lp-mono">How it works</p>
            <h2 className="lp-h2">From scattered alerts to one incident</h2>
            <ol className="lp-steps">
              {STEPS.map((s) => (
                <li key={s.n}>
                  <span className="lp-mono">{s.n}</span>
                  <h3>{s.title}</h3>
                  <p>{s.text}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="lp-sec lp-pad" id="wins" data-reveal>
          <div className="lp-wrap">
            <p className="lp-mono">What sets it apart</p>
            <h2 className="lp-h2">Graph-native security triage</h2>
            <div className="lp-wins">
              {WINS.map((w) => (
                <article key={w.title} className="lp-card" data-tint={w.tint}>
                  <h3>{w.title}</h3>
                  <p>{w.text}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="lp-sec lp-final" data-reveal>
          <div className="lp-wrap">
            <h2 className="lp-h2"><span>See one attack</span><span className="lp-accent">connect itself.</span></h2>
            <p>The console runs on a fictional sample organisation. Nothing to install, nothing to sign up for.</p>
            <a className="lp-btn lp-btn-lg" href="#/console">Open the console<Arrow /></a>
          </div>
        </section>
      </main>

      <footer className="lp-foot">
        <div className="lp-wrap">
          <div className="lp-brand"><Logo />GraphOps</div>
          <p>Team Pingu Haters: Deepthi Sree Dubasi, Vatanesh Sharma, Bhanu Sai Teja, Raja Mohamad and SK MD Mahasin.</p>
          <p className="lp-muted">The console runs on a fictional sample organisation. All data is synthetic.</p>
        </div>
      </footer>
    </div>
  );
}
