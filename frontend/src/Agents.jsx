import { useEffect, useState } from "react";
import { getAgent, getSources } from "./api.js";
import { Info } from "./parts.jsx";

const POLL_MS = 4000;
const STEP = {
  FeedsUntrustedInput: "reads untrusted web content →", CanRead: "can read", Contains: "contains",
  HoldsKeyFor: "holds keys for", SignedInTo: "is signed in to", HasToolAccess: "can call",
};
const TECH = { FeedsUntrustedInput: "AML.T0051.001", CanRead: "T1005", HoldsKeyFor: "T1552.001", SignedInTo: "T1078.004" };
const FIX = {
  HoldsKeyFor: "Move this key out of the file into a secrets manager, and rotate it",
  CanRead: "Narrow the agent's readable folders (block reads outside the working folder)",
  SignedInTo: "Give the agent a scoped token instead of your full account",
  FeedsUntrustedInput: "Require approval before the agent acts on web content",
};
const HOW = { CanRead: "can read", SignedInTo: "signed in", HasToolAccess: "tool" };

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

// a real ai agent reporting from a team laptop: what it can reach (access scan), what it actually did (a hook
// after every tool call) and the routes from the open web through it to critical services
export default function Agents({ onError }) {
  const [sources, setSources] = useState(null);
  const [view, setView] = useState(null);
  const [pick, setPick] = useState(null);

  useEffect(() => {
    getSources().then((all) => setSources(all.filter((s) => s.kind === "ai_agent"))).catch((e) => onError(e.message));
  }, []); // eslint-disable-line

  // several team members can connect their agents; the most recently active one shows first
  const id = pick || sources?.[0]?.id;
  useEffect(() => {
    if (!id) return;
    let stop = false, timer;
    const tick = () => getAgent(id).then((v) => { if (!stop) setView(v); }).catch(() => {})
      .finally(() => { if (!stop) timer = setTimeout(tick, POLL_MS); });
    tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [id]);

  if (!sources) return <div className="view-loading">Loading…</div>;
  if (!sources.length) return (
    <div className="view-loading">No AI agent is reporting yet. Run <code>collectors/claude_code/scan.py</code> on a laptop with Claude Code.</div>
  );
  if (!view) return <div className="view-loading">Loading…</div>;

  const names = Object.fromEntries([...view.reach, ...view.secrets, ...view.services].map((x) => [x.id, x.name]));
  names[view.agent.id] = view.agent.name;
  names.internet = "The internet";
  const sm = view.summary;
  const fresh = view.last_seen && Date.now() - new Date(view.last_seen).getTime() < 120000;

  return (
    <main className="agents">
      {sources.length > 1 && (
        <div className="ag-pick" role="tablist" aria-label="AI agents reporting">
          {sources.map((s) => (
            <button key={s.id} role="tab" aria-selected={s.id === id} className={s.id === id ? "on" : ""}
              onClick={() => { setPick(s.id); setView(null); }}>{s.id.replace(/^claude-code-/, "Claude Code · ")}</button>
          ))}
        </div>
      )}
      <section className="panel ag-head">
        <div className="ag-id">
          <span className={`live-dot ${fresh ? "pulse" : ""}`} />
          <div>
            <h2>{view.agent.name}<span className="ag-real">real</span></h2>
            <small>{view.agent.platform} · on {view.agent.host} · last activity {ago(view.last_seen)} · access scanned {ago(view.inventory_at)}</small>
          </div>
          <Info text="An AI agent running on a team member's laptop. A scan reports what it can reach (names only, never file contents or key values). A hook reports each action it takes, live." />
        </div>
        <div className="ag-stats">
          <div><b>{sm.folders}</b><span>folders it can read{view.agent.home_readable ? ", incl. the whole home folder" : ""}</span></div>
          <div className="warn"><b>{sm.secrets}</b><span>secret files within reach</span></div>
          <div className="crit"><b>{sm.services}</b><span>services those keys open, {sm.critical_services} critical</span></div>
          <div><b>{sm.tools}</b><span>tools, {view.reach.filter((r) => r.kind === "Tool" && /web|browser/i.test(r.name)).length} read the open web</span></div>
          <div><b>{sm.used} of {sm.granted}</b><span>used in the last {sm.days} days</span></div>
        </div>
      </section>

      {view.history && (
        <section className="panel ag-hist">
          <div className="panel-head">
            <h2>History</h2>
            <small>{view.history.sessions} sessions · {view.history.tool_calls.toLocaleString()} actions since {new Date(view.history.first).toLocaleDateString()}</small>
            <Info text="Read from Claude Code's own session logs on this laptop, by the access scan. Only counts are sent: no project names, file contents or commands." />
          </div>
          <div className="ag-hist-row">
            {[["read the open web", "web pages read"], ["AWS command line", "AWS commands run"], ["git push", "git pushes"],
              ["GitHub CLI", "GitHub CLI calls"], ["read or edited a secret file", "secret files opened"]].map(([k, label]) => (
              <div key={k} className={k === "read or edited a secret file" ? (view.history.notable[k] ? "crit" : "ok") : ""}>
                <b>{(view.history.notable[k] || 0).toLocaleString()}</b><span>{label}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="ag-grid">
        <section className="panel">
          <div className="panel-head">
            <h2>If this agent is hijacked</h2>
            <small>routes from the open web to critical services</small>
            <Info text="Indirect prompt injection: a web page the agent reads carries instructions. From there the agent's own access is the attacker's access. Each step is tagged with its MITRE ATT&CK or ATLAS technique." />
          </div>
          {view.attack_paths.length === 0 && <p className="ag-none">No route from the open web to a critical service.</p>}
          {view.attack_paths.map((p) => (
            <div key={p.target} className="ag-path">
              <div className="ag-path-to">to <b>{p.target_name}</b> · {p.types.length} steps</div>
              <ol>
                {p.nodes.map((n, i) => (
                  <li key={n}>
                    <code className={i === p.nodes.length - 1 ? "crit" : ""}>{names[n] || n}</code>
                    {i < p.types.length && <em>{STEP[p.types[i]] || p.types[i]}{TECH[p.types[i]] && <span> {TECH[p.types[i]]}</span>}</em>}
                  </li>
                ))}
              </ol>
              {(() => { const t = p.types.find((x) => x === "HoldsKeyFor") || p.types.find((x) => FIX[x] && x !== "FeedsUntrustedInput");
                return t && <div className="ag-fix">Fix: {FIX[t]}</div>; })()}
            </div>
          ))}
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Live activity</h2>
            <small>each tool call, as it happens</small>
            <Info text="Sent by a Claude Code hook after every tool call: the tool and what it touched. No file contents, command output or arguments beyond the first word of a command." />
          </div>
          <ul className="ag-feed">
            {view.events.length === 0 && <li className="ag-none">No activity yet.</li>}
            {view.events.map((e, i) => (
              <li key={i} className={/^secret:/.test(e.target) ? "secret" : ""}>
                <span className="t">{new Date(e.time).toLocaleTimeString()}</span>
                <span className="tool">{e.tool}</span>
                <span className="what">{e.detail}</span>
                <span className="tgt">{names[e.target] || e.target}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Access: granted vs used</h2>
          <small>last {sm.days} days</small>
          <Info text="Everything the agent can reach, and whether it actually used it. Access it never uses is access you can remove, the same least-privilege idea as the Access tab." />
        </div>
        <table className="ag-table">
          <thead><tr><th>What</th><th>How</th><th>Opens</th><th>Last {sm.days} days</th><th>All sessions</th></tr></thead>
          <tbody>
            {view.reach.filter((r) => r.kind !== "Tool").map((r) => (
              <tr key={r.id}><td>{r.name}{r.critical && <span className="ag-crit">critical</span>}</td><td>{HOW[r.how] || r.how}</td>
                <td>{r.keys.length ? `${r.keys.length} secret file${r.keys.length > 1 ? "s" : ""}` : "–"}</td>
                <td className={r.used ? "yes" : "no"}>{r.used ? `${r.used}× · ${ago(r.last_used)}` : "not used"}</td><td>{r.ever ? `${r.ever.toLocaleString()}×` : "never"}</td></tr>
            ))}
            {view.secrets.map((s) => (
              <tr key={s.id}><td><code>{s.name}</code></td><td>secret file</td><td>{s.services.join(", ") || "–"}</td>
                <td className={s.used ? "warn" : "no"}>{s.used ? `read ${s.used}×` : "not read"}</td><td className={s.ever ? "warn" : ""}>{s.ever ? `${s.ever}×` : "never"}</td></tr>
            ))}
            {view.reach.filter((r) => r.kind === "Tool").map((r) => (
              <tr key={r.id}><td>{r.name}</td><td>tool</td><td>–</td>
                <td className={r.used ? "yes" : "no"}>{r.used ? `${r.used}× · ${ago(r.last_used)}` : "not used"}</td><td>{r.ever ? `${r.ever.toLocaleString()}×` : "never"}</td></tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}
