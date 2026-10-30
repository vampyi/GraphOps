import { useEffect, useState } from "react";
import { getProof } from "./api.js";
import { Info } from "./parts.jsx";

// does the ranking work? every labelled day, graphops against sorting by the tools' own severity
export default function Proof() {
  const [data, setData] = useState(null);
  useEffect(() => { getProof().then(setData).catch(() => {}); }, []);
  if (!data) return null;
  const won = data.days.filter((d) => d.graphops.last_attack_rank < d.severity.last_attack_rank).length;
  return (
    <section className="panel proof">
      <div className="panel-head">
        <h2>Proof</h2>
        <small>GraphOps vs sorting by severity, on every labelled day</small>
        <Info text="Each day hides an attack among noise. The ranking never sees the labels; they are only used to score it. The tuning day is the one the weights were set on. Five held-out days are synthetic, written by us around known weaknesses. The APT29 day is MITRE's real lab recording (OTRF Security Datasets); its alerts come from our rules on the real events and the attack labels are ours, from the published emulation plan." />
      </div>
      <p className="proof-head">GraphOps ranked the attack higher than severity sorting on <b>{won} of {data.days.length}</b> days.</p>
      <table className="proof-table">
        <thead>
          <tr><th>Day</th><th>Alerts</th><th>Attack alerts</th>
            <th>Last attack alert's rank<Info text="Where the last attack alert sits in the list. Lower means the whole attack is found sooner." /></th>
            <th>False alarms read first<Info text="How many harmless alerts an analyst reads before the first attack alert." /></th>
            <th>Attack split into</th></tr>
        </thead>
        <tbody>
          {data.days.map((d) => (
            <tr key={d.scenario}>
              <td>{d.name}{d.scenario === "sample" && <span className="proof-tag">tuning day</span>}{d.scenario.startsWith("apt29") && <span className="proof-tag real">real lab logs</span>}</td>
              <td>{d.alerts}</td><td>{d.attack}</td>
              <td><b className="go">{d.graphops.last_attack_rank}</b> <span className="vs">vs</span> <span className="sev">{d.severity.last_attack_rank}</span></td>
              <td><b className="go">{d.graphops.false_before_first}</b> <span className="vs">vs</span> <span className="sev">{d.severity.false_before_first}</span></td>
              <td>{d.attack_incidents} incident{d.attack_incidents > 1 ? "s" : ""}{d.noise_in_attack_incidents ? `, ${d.noise_in_attack_incidents} noise pulled in` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="proof-note">GraphOps first, severity second. Measured {data.measured}. On the real APT29 recording the attack and the noise sit on the same two machines within 33 minutes, so the graph cannot separate them and ranks like severity; the file server ransomware day shows the same limit.</p>
    </section>
  );
}
