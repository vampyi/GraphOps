import { useEffect, useRef, useState } from "react";
import { askQuestion, getLanguages } from "./api.js";
import { Cites, Info } from "./parts.jsx";

const SUGGESTIONS = [
  "Which alert should I look at first, and why?",
  "What can laptop-42 reach?",
  "Explain the incident behind the top alert in simple words.",
  "Which permission should we remove first to cut attack paths?",
  "Which accounts hold access they never use?",
  "How does GraphOps compare with sorting by severity today?",
];
const TOOL_LABEL = {
  top_alerts: "top alerts", alert_details: "one alert", blast_radius: "blast radius", incident: "an incident",
  attack_paths: "attack paths", access_gap: "access gap", ranking_quality: "ranking quality", find_entities: "entity search",
};

// the ask tab: plain-language questions, answered only from graphops' own read-only lookups, every sentence
// citing the alerts, users or machines it is based on.
export default function Ask() {
  const [turns, setTurns] = useState([]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(true);
  const end = useRef(null);

  useEffect(() => {
    getLanguages().then((d) => setReady(d.llm)).catch(() => {});
  }, []);
  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [turns, busy]);

  const send = async (q) => {
    const question = (q ?? text).trim();
    if (!question || busy) return;
    setText("");
    const history = turns.flatMap((t) => [
      { role: "user", content: t.question },
      ...(t.answer ? [{ role: "assistant", content: t.answer.sentences.map((s) => s.text_en || s.text).join(" ") }] : []),
    ]);
    setTurns((ts) => [...ts, { question }]);
    setBusy(true);
    try {
      const answer = await askQuestion(question, history, "en-IN");
      setTurns((ts) => ts.map((t, i) => (i === ts.length - 1 ? { ...t, answer } : t)));
    } catch (e) {
      const msg = e.message.startsWith("503") ? "Unavailable: no AI key on this server"
        : e.message.startsWith("502") ? "The AI service did not respond. Try again." : "Something went wrong. Try again.";
      setTurns((ts) => ts.map((t, i) => (i === ts.length - 1 ? { ...t, error: msg } : t)));
    }
    setBusy(false);
  };

  return (
    <main className="ask">
      <section className="panel ask-chat">
        <header className="ask-head">
          <h2>Ask GraphOps<Info text="Answers come only from GraphOps' own read-only lookups: alerts, blast radius, incidents, attack paths and access. Each sentence cites what it is based on; a sentence citing anything else is removed. Powered by Sarvam AI." /></h2>
        </header>

        {!ready && <div className="ask-note">Unavailable: no AI key on this server</div>}

        <div className="ask-log">
          {!turns.length && (
            <div className="ask-empty">
              <div className="ask-empty-h">Suggested</div>
              <div className="ask-sugs">
                {SUGGESTIONS.map((s) => <button key={s} onClick={() => send(s)} disabled={busy}>{s}</button>)}
              </div>
            </div>
          )}
          {turns.map((t, i) => (
            <div key={i} className="ask-turn">
              <div className="ask-q">{t.question}</div>
              {t.error && <div className="ask-err">{t.error}</div>}
              {t.answer && <Answer a={t.answer} />}
              {!t.answer && !t.error && busy && i === turns.length - 1 && <div className="ask-wait">Looking up…</div>}
            </div>
          ))}
          <div ref={end} />
        </div>

        <form className="ask-input" onSubmit={(e) => { e.preventDefault(); send(); }}>
          <input value={text} onChange={(e) => setText(e.target.value)} maxLength={500}
            placeholder="Ask about alerts, machines, people or attack paths" aria-label="Your question" />
          <button className="btn primary" disabled={busy || !text.trim()}>{busy ? "Thinking…" : "Ask"}</button>
        </form>
      </section>
    </main>
  );
}

function Answer({ a }) {
  const sources = [...new Set(a.tools_used.map((u) => TOOL_LABEL[u.tool] || u.tool))];
  return (
    <div className="ask-a">
      {a.sentences.length
        ? a.sentences.map((s, i) => (
          <p key={i}>{s.text} <Cites ids={s.cites} />
            {s.text_en && <span className="story-en">{s.text_en}</span>}
          </p>))
        : <p>No supported answer.</p>}
      <div className="ask-meta">
        <span className="tag-ai">AI draft</span>
        {sources.map((x) => <span key={x} className="src-tag">{x}</span>)}
        {a.dropped?.length > 0 && <span className="tag-ai off">{a.dropped.length} unsupported sentence{a.dropped.length > 1 ? "s" : ""} removed</span>}
        {a.translation_error && <span className="tag-ai off">Translation unavailable</span>}
      </div>
    </div>
  );
}
