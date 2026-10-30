import { useEffect, useState } from "react";
import { confirmIncident, getCertIn, getRespond, notifyIncident, requestStep } from "./api.js";
import { Info } from "./parts.jsx";

function left(deadline, now) {
  const ms = new Date(deadline).getTime() - now;
  if (ms <= 0) return "overdue";
  const h = Math.floor(ms / 3600000), m = Math.floor((ms % 3600000) / 60000), s = Math.floor((ms % 60000) / 1000);
  return `${h}h ${String(m).padStart(2, "0")}m ${String(s).padStart(2, "0")}s`;
}

// respond to a confirmed incident: who to tell, what to contain, the CERT-In clock, a report draft and a real email
export default function Respond({ incident, onError, onDraft }) {
  const [plan, setPlan] = useState(null);
  const [to, setTo] = useState([]);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!incident) return;
    setPlan(null); setSent(null);
    getRespond(incident.id).then(setPlan).catch((e) => onError(e.message));
  }, [incident?.id]); // eslint-disable-line
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);

  if (!incident) return <div className="tab-pane"><div className="live-empty">Not linked to other alerts</div></div>;
  if (!plan) return <div className="tab-pane"><div className="view-loading">Loading…</div></div>;

  const act = (p) => p.then(setPlan).catch((e) => onError(e.message));
  const send = async () => {
    setSending(true);
    try {
      const r = await notifyIncident(incident.id, to, window.location.href);
      setPlan(r.plan); setSent(r.sent); setTo([]);
    } catch (e) {
      onError(e.message.startsWith("503") ? "Email is not set up on this server." : `Could not send: ${e.message}`);
    }
    setSending(false);
  };

  return (
    <div className="tab-pane respond">
      {!plan.confirmed_at ? (
        <div className="rs-confirm">
          <div>
            <b>Is this a real attack?</b>
            <span>Confirming starts the 6-hour CERT-In reporting clock.</span>
          </div>
          <button className="btn primary small" onClick={() => act(confirmIncident(incident.id))}>Confirm incident</button>
        </div>
      ) : (
        <div className={`rs-clock ${new Date(plan.cert_in_deadline).getTime() - now < 3600000 ? "late" : ""}`}>
          <div>
            <span className="rs-l">CERT-In report due in<Info text="Under the CERT-In Directions of 28 April 2022, cyber incidents must be reported to CERT-In within 6 hours of noticing them. The clock started when the incident was confirmed." /></span>
            <b>{left(plan.cert_in_deadline, now)}</b>
            <small>confirmed {new Date(plan.confirmed_at).toLocaleTimeString()}</small>
          </div>
          <button className="btn small" onClick={() => getCertIn(incident.id).then((d) => onDraft({ id: `${incident.id}-cert-in`, markdown: d.markdown })).catch((e) => onError(e.message))}>
            CERT-In report draft
          </button>
        </div>
      )}

      <h3 className="pane-h">Who needs to know<Info text="From the graph: the accounts in the incident, the owners of its machines, and the owner of the nearest critical asset it can reach." /></h3>
      <ul className="rs-list">
        {plan.notify.map((n) => <li key={n.who}><code>{n.who}</code><span>{n.why}</span></li>)}
      </ul>

      <h3 className="pane-h">Containment<Info text="Steps worked out from the graph. GraphOps records each as requested, with a time; carrying it out is done in the EDR, directory or firewall." /></h3>
      <ul className="rs-steps">
        {plan.steps.map((s) => (
          <li key={s.id} className={s.requested_at ? "done" : ""}>
            <label>
              <input type="checkbox" checked={!!s.requested_at} onChange={(e) => act(requestStep(incident.id, s.id, e.target.checked))} />
              <span>{s.text}</span>
            </label>
            {s.requested_at && <small>requested {new Date(s.requested_at).toLocaleTimeString()}</small>}
          </li>
        ))}
      </ul>

      <h3 className="pane-h">Notify by email<Info text="Sends a real email with how it started, who is involved, the containment steps and the CERT-In deadline. Only the team contacts set up on this server can be emailed, a few per incident." /></h3>
      {!plan.email_ready
        ? <p className="rs-note">Email is not set up on this server.</p>
        : (
          <>
            <div className="rs-contacts">
              {plan.contacts.map((c) => (
                <label key={c.name} className={to.includes(c.name) ? "on" : ""}>
                  <input type="checkbox" checked={to.includes(c.name)} onChange={(e) => setTo(e.target.checked ? [...to, c.name] : to.filter((x) => x !== c.name))} />
                  <span>{c.name}{c.role && <small>{c.role}</small>}</span><em>{c.email}</em>
                </label>
              ))}
            </div>
            <button className="btn primary small" disabled={!to.length || sending} onClick={send}>{sending ? "Sending…" : `Send to ${to.length || "…"}`}</button>
            {sent && <span className="rs-sent">Sent to {sent.join(", ")}</span>}
          </>
        )}
      {plan.emails.length > 0 && <p className="rs-note">Emailed: {plan.emails.map((e) => `${e.to} at ${new Date(e.at).toLocaleTimeString()}`).join(" · ")}</p>}
    </div>
  );
}
