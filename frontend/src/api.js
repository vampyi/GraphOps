async function call(path, options) {
  const res = await fetch(`/api${path}`, options);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

const post = (path, body) =>
  call(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
const patch = (path, body) =>
  call(path, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

// triage
export const getAlerts = () => call("/alerts");
export const getBlastRadius = (id, mode = "all", days = 30) => call(`/alerts/${id}/blast-radius?mode=${mode}&days=${days}`);
export const getIncident = (id) => call(`/incidents/${id}`);
export const getReport = (id) => call(`/incidents/${id}/report`);
export const patchIncident = (id, body) => patch(`/incidents/${id}`, body);
export const writeStory = (id, lang = "en-IN") => post(`/incidents/${id}/story?lang=${encodeURIComponent(lang)}`);
export const getLanguages = () => call("/languages");
export const askQuestion = (question, history, lang) => post("/ask", { question, history, lang });
export const setVerdict = (id, status, by) => post(`/alerts/${id}/verdict`, { status, by });
export const patchAsset = (id, body) => patch(`/assets/${id}`, body);

// exposure
export const getExposure = (scope = "low_trust", maxHops = 6) => call(`/exposure?scope=${scope}&max_hops=${maxHops}`);
export const simulateExposure = (body) => post("/exposure/simulate", body);

// access and communities
export const getAccess = (id, days = 30) => call(`/entities/${encodeURIComponent(id)}/access?days=${days}`);
export const getAccessOverview = (days = 30) => call(`/access/overview?days=${days}`);
export const getCommunities = () => call("/communities");

// evaluation and scenarios (credibility)
export const getEvaluation = () => call("/evaluation");
export const getLearning = () => call("/learning");
export const getScenarios = () => call("/scenarios");
export const loadScenario = (id) => post(`/scenarios/${id}/load`);

// graph engine (the Neo4j showcase)
export const getGraphAlgorithms = () => call("/graph/algorithms");
export const getReachabilityProof = (src, dst) =>
  call(`/graph/reachability-proof?src=${encodeURIComponent(src)}${dst ? `&dst=${encodeURIComponent(dst)}` : ""}`);

// live replay
export const getLive = (since = 0) => call(`/live?since=${since}`);
export const replayReset = () => post("/replay/reset");
export const replayStart = (attack, speed) => post("/replay/start", { attack, speed });

// explore
export const getEntities = () => call("/entities");
export const getExplore = (id, maxHops = 5) => call(`/explore/${encodeURIComponent(id)}?max_hops=${maxHops}`);
export const setControl = (body) => post("/controls", body);
