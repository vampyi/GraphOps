import Logo from "./Logo.jsx";
import ThemeToggle from "./Theme.jsx";

const STATS = [
  { value: "73%", label: "of SANS 2025 survey respondents cited false positives as a main detection challenge", source: "SANS Institute" },
  { value: "29 min", label: "average time for an attacker to start spreading inside a network in 2025", source: "CrowdStrike" },
  { value: "₹25.5 cr", label: "average cost of a data breach in India in 2026, a record high", source: "IBM" },
  { value: "6 hours", label: "to report a cyber incident to CERT-In after noticing it", source: "CERT-In" },
];

const PAINS = [
  { title: "Too many alarms", status: "live", problem: "Most alerts are false, so the real attack hides in the noise.", fix: "Ranks every alert by where it sits on the attacker's map. Nothing is deleted." },
  { title: "Alerts don't connect", status: "live", problem: "One attack shows up as many separate alerts.", fix: "Links alerts along the path the attacker took and orders them by attack stage." },
  { title: "Attackers are faster", status: "live", problem: "Attackers spread in minutes while analysts take hours.", fix: "Works out each machine's distance to critical assets ahead of time, so scoring is instant." },
  { title: "How bad is this?", status: "live", problem: "Nobody can quickly see what a hacked machine can reach.", fix: "Draws the 1, 2 and 3 hop blast radius around any alert." },
  { title: "Hidden danger", status: "planned", problem: "Risky access paths exist long before anyone uses them.", fix: "Maps attack paths and choke points before any attack." },
  { title: "Too much access", status: "planned", problem: "People hold far more access than they use.", fix: "Compares the blast radius over granted access with access actually used." },
  { title: "One step at a time", status: "live", problem: "Each step can look normal while the whole route is strange.", fix: "Flags a user reaching a system through a route they have never used." },
];

const STEPS = [
  { n: "01", title: "Collect", text: "Logins, permissions, machines and alerts stream in from a company's existing tools." },
  { n: "02", title: "Connect", text: "Everything becomes one Neo4j graph: users, machines and groups as dots, logins and permissions as lines." },
  { n: "03", title: "Rank", text: "Each alert is scored on six graph questions and linked to the alerts on the same attack path." },
  { n: "04", title: "Explain", text: "The analyst sees the blast radius, the attack in stage order and an AI-drafted story that cites its facts." },
];

export default function Landing() {
  return (
    <div className="landing">
      <nav className="lnav">
        <div className="brand"><Logo />GraphOps</div>
        <div className="lnav-links">
          <a href="#problem" onClick={(e) => { e.preventDefault(); document.getElementById("problem").scrollIntoView({ behavior: "smooth" }); }}>Problem</a>
          <a href="#how" onClick={(e) => { e.preventDefault(); document.getElementById("how").scrollIntoView({ behavior: "smooth" }); }}>How it works</a>
          <ThemeToggle />
          <a className="btn primary small" href="#/demo">Open the live demo</a>
        </div>
      </nav>

      <header className="hero">
        <h1>Defenders think in lists.<br /><span>Attackers think in graphs.</span></h1>
        <p className="quote-by">John Lambert, Microsoft</p>
        <p className="lead">
          GraphOps ranks every security alert by where it sits on the attacker's map, links scattered alerts into one
          incident and shows what an attacker can reach next. One open graph, built on Neo4j.
        </p>
        <div className="cta">
          <a className="btn primary" href="#/demo">Open the live demo</a>
          <a className="btn ghost" href="#how" onClick={(e) => { e.preventDefault(); document.getElementById("how").scrollIntoView({ behavior: "smooth" }); }}>How it works</a>
        </div>
        <p className="made-for">Built by Team Pingu Haters for hackFront India 2026, Cybersecurity theme.</p>
        <div className="hero-word">GRAPHOPS</div>
      </header>

      <section className="stats">
        {STATS.map((s) => (
          <div key={s.value} className="stat">
            <div className="stat-value">{s.value}</div>
            <div className="stat-label">{s.label}</div>
            <div className="stat-src">Source: {s.source}</div>
          </div>
        ))}
      </section>

      <section id="problem" className="section">
        <p className="kicker">The seven pain points</p>
        <h2>What keeps a security team from seeing the attack</h2>
        <div className="pains">
          {PAINS.map((p, i) => (
            <div key={p.title} className="pain">
              <div className="pain-head">
                <h3>{p.title}</h3>
                <span className={`badge ${p.status}`}>{p.status === "live" ? "In the demo" : "Planned"}</span>
              </div>
              <p className="pain-problem">{p.problem}</p>
              <p className="pain-fix">{p.fix}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="how" className="section">
        <p className="kicker">How it works</p>
        <h2>From scattered alerts to one connected story</h2>
        <div className="steps">
          {STEPS.map((s, i) => (
            <div key={s.n} className="step">
              <h3>{s.title}{i < STEPS.length - 1 && <span className="arrow">→</span>}</h3>
              <p>{s.text}</p>
            </div>
          ))}
        </div>
        <div className="cta center"><a className="btn primary" href="#/demo">See it on a demo company</a></div>
      </section>

      <footer className="lfoot">
        Team Pingu Haters: Deepthi Sree Dubasi, Vatanesh Sharma, Bhanu Sai Teja, Raja Mohamad and SK MD Mahasin.
        <br />The demo uses a fictional company. All data is synthetic.
      </footer>
    </div>
  );
}
