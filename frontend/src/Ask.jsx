import { useEffect, useRef, useState } from "react";
import { askQuestion, getLanguages } from "./api.js";

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
  const [lang, setLang] = useState("en-IN");
  const [languages, setLanguages] = useState([{ code: "en-IN", name: "English" }]);
  const [ready, setReady] = useState(true);
  const end = useRef(null);

  useEffect(() => {
    getLanguages().then((d) => { setLanguages(d.languages); setReady(d.llm); }).catch(() => {});
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
      const answer = await askQuestion(question, history, lang);
      setTurns((ts) => ts.map((t, i) => (i === ts.length - 1 ? { ...t, answer } : t)));
    } catch (e) {
      const msg = e.message.startsWith("503") ? "The Ask tab needs a Sarvam AI key on the server. It is not set yet."
        : e.message.startsWith("502") ? "The AI service did not answer. Try again in a moment." : `Something went wrong: ${e.message}`;
      setTurns((ts) => ts.map((t, i) => (i === ts.length - 1 ? { ...t, error: msg } : t)));
    }
    setBusy(false);
  };

  return (
    <main className="ask">
      <section className="panel ask-chat">
        <header className="ask-head">
          <div>
            <h2>Ask GraphOps</h2>
            <p>Ask in plain words. The answer comes only from what GraphOps has already worked out, and every sentence shows the alerts, people or machines it is based on. Sentences that cite anything else are removed.</p>
          </div>
          <label className="ask-lang">Answer in
            <select value={lang} onChange={(e) => setLang(e.target.value)}>
              {languages.map((l) => <option key={l.code} value={l.code}>{l.name}</option>)}
            </select>
          </label>
        </header>

        {!ready && <div className="ask-note">The AI key is not set on this server, so questions cannot be answered yet.</div>}

        <div className="ask-log">
          {!turns.length && (
            <div className="ask-empty">
              <div className="ask-empty-h">Try one of these</div>
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
              {!t.answer && !t.error && busy && i === turns.length - 1 && <div className="ask-wait">Looking it up…</div>}
            </div>
          ))}
          <div ref={end} />
        </div>

        <form className="ask-input" onSubmit={(e) => { e.preventDefault(); send(); }}>
          <input value={text} onChange={(e) => setText(e.target.value)} maxLength={500}
            placeholder="For example: what can the intern's laptop reach?" aria-label="Your question" />
          <button className="btn primary" disabled={busy || !text.trim()}>{busy ? "Thinking…" : "Ask"}</button>
        </form>
      </section>
    </main>
  );
}

function Answer({ a }) {
  return (
    <div className="ask-a">
      {a.sentences.length
        ? a.sentences.map((s, i) => (
          <p key={i}>{s.text} {s.cites.map((c) => <code key={c}>{c}</code>)}
            {s.text_en && <span className="story-en">{s.text_en}</span>}
          </p>))
        : <p>No answer passed the citation check.</p>}
      <div className="ask-meta">
        {a.tools_used.length ? <>Looked up: {[...new Set(a.tools_used.map((u) => TOOL_LABEL[u.tool] || u.tool))].join(", ")}</> : "No lookups were needed"}
        {a.dropped?.length > 0 && <> · {a.dropped.length} sentence{a.dropped.length > 1 ? "s" : ""} removed for citing something the lookups did not return</>}
        {a.translation_error && <> · translation failed, shown in English</>}
        <> · Drafted by AI (Sarvam), check before acting</>
      </div>
    </div>
  );
}
