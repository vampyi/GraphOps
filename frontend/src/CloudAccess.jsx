import { useEffect, useState } from "react";
import { getCloudAws, refreshCloudAws } from "./api.js";
import { Info } from "./parts.jsx";

const LEVEL = { admin: "Administrator", write: "Can change resources", read: "Read only", custom: "Custom policy", none: "No permissions" };
const ago = (iso) => {
  if (!iso) return "never";
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  return d < 1 ? "today" : `${d} d ago`;
};

// the connected aws account, read live with a read-only key: each identity's rights against what it actually used,
// and the findings worth acting on. the same identities sit in the graph, so attack paths can run into aws.
export default function CloudAccess({ onError }) {
  const [v, setV] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { getCloudAws().then(setV).catch(() => setV({ connected: false })); }, []);
  const refresh = async () => {
    setBusy(true);
    try { setV(await refreshCloudAws()); } catch (e) {
      onError(e.message.startsWith("503") ? "No AWS key on this server." : `Could not read AWS: ${e.message}`);
    }
    setBusy(false);
  };
  if (!v) return null;
  return (
    <section className="panel cloud-acc">
      <div className="panel-head">
        <h2>AWS account{v.connected && <span className="ag-real">live</span>}</h2>
        <small>{v.connected ? `account …${v.account} · read ${ago(v.fetched)}` : "not connected"}</small>
        <Info text="Read with a read-only key (AWS's SecurityAudit policy): IAM users, roles and their policies, MFA, and when each password and access key was last used. These identities also sit in the graph, so attack paths can run from a laptop or an AI agent into AWS." />
        {v.configured && <button className="linkish cloud-refresh" disabled={busy} onClick={refresh}>{busy ? "Reading…" : v.connected ? "Refresh" : "Connect"}</button>}
      </div>
      {!v.connected
        ? <p className="rs-note">{v.configured ? "Press Connect to read the account." : "No AWS key on this server."}</p>
        : (
          <>
            {v.findings.length > 0 && (
              <ul className="cloud-findings">
                {v.findings.map((f, i) => (
                  <li key={i} className={f.severity}>
                    <span className="sev-pill">{f.severity}</span>
                    <span><code>{f.who}</code> {f.text}</span>
                    <em>{f.fix}</em>
                  </li>
                ))}
              </ul>
            )}
            <table className="ag-table">
              <thead><tr><th>Identity</th><th>Rights</th><th>MFA</th><th>Keys</th><th>Last used</th></tr></thead>
              <tbody>
                {v.identities.map((i) => {
                  const last = [i.password_last_used, ...i.keys.map((k) => k.last_used)].filter(Boolean).sort().pop();
                  return (
                    <tr key={`${i.kind}/${i.name}`}>
                      <td><code>{i.name}</code> <small className="cloud-kind">{i.kind}</small></td>
                      <td className={i.level === "admin" ? "warn" : ""} title={i.policies.join(", ")}>{LEVEL[i.level] || i.level}</td>
                      <td className={i.kind === "role" ? "" : i.mfa ? "yes" : "no"}>{i.kind === "role" ? "–" : i.mfa ? "on" : "off"}</td>
                      <td>{i.keys.length || "–"}</td>
                      <td className={last ? "" : "no"}>{i.kind === "role" ? "–" : ago(last)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
    </section>
  );
}
