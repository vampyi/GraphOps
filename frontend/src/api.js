async function call(path, options) {
  const res = await fetch(`/api${path}`, options);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export const getAlerts = () => call("/alerts");
export const getBlastRadius = (id) => call(`/alerts/${id}/blast-radius`);
export const getIncident = (id) => call(`/incidents/${id}`);
export const writeStory = (id) => call(`/incidents/${id}/story`, { method: "POST" });
export const setVerdict = (id, status) =>
  call(`/alerts/${id}/verdict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
