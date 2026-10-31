import { useEffect, useState } from "react";
import { getSources } from "./api.js";
import { Info } from "./parts.jsx";

const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
};
const flag = (v, good, bad) => (v == null ? <span className="src-na">unknown</span> : v ? <span className="src-ok">{good}</span> : <span className="src-bad">{bad}</span>);

// real machines reporting into the graph right now, next to the synthetic sample organisation
export default function Sources() {
  const [list, setList] = useState(null);
  useEffect(() => {
    let t;
    const tick = () => getSources().then(setList).catch(() => setList([])).finally(() => { t = setTimeout(tick, 15000); });
    tick();
    return () => clearTimeout(t);
  }, []);
  if (!list) return null;
  const endpoints = list.filter((s) => s.kind === "endpoint");
  return (
    <section className="panel sources">
      <div className="panel-head">
        <h2>Connected sources</h2>
        <small>{endpoints.length ? `${endpoints.length} real laptop${endpoints.length > 1 ? "s" : ""} reporting` : "none reporting"}</small>
        <Info text="Team laptops running osquery report their accounts, admins, sign-ins, listening ports, disk encryption and firewall every minute. Each change becomes an alert in Triage, and each laptop is a node in this graph, next to the synthetic sample organisation. Account names are masked." />
      </div>
      {endpoints.length === 0
        ? <p className="rs-note">No laptop is reporting. See collectors/osquery/README.md to connect one.</p>
        : (
          <table className="proof-table">
            <thead><tr><th>Laptop</th><th>OS</th><th>Accounts</th><th>Listening ports</th><th>Disk encryption</th><th>Firewall</th><th>Changes</th><th>Last report</th></tr></thead>
            <tbody>
              {endpoints.map((s) => {
                const live = s.last_seen && Date.now() - new Date(s.last_seen).getTime() < 180000;
                return (
                  <tr key={s.id}>
                    <td><span className={`live-dot ${live ? "pulse" : ""}`} /> {s.label}</td>
                    <td>{s.os}</td>
                    <td>{s.users} ({s.admins} admin)</td>
                    <td>{s.listening}</td>
                    <td>{flag(s.disk_encrypted, "on", "off")}</td>
                    <td>{flag(s.firewall, "on", "off")}</td>
                    <td>{s.events}</td>
                    <td className={live ? "yes" : "no"}>{ago(s.last_seen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
    </section>
  );
}
