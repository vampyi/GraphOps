import { useEffect, useState } from "react";
import Landing from "./Landing.jsx";
import Dashboard from "./Dashboard.jsx";

// routing is hash-based so it works on any static host and never asks the server for a path it does not have:
//   #/                     landing
//   #/console              the console (Triage view)
//   #/console/exposure     the console, Exposure view
//   #/console/access       the console, Access view
// a plain path like /console (from a refresh or a typed url) is also accepted: the server serves index.html and
// we treat it the same as #/console, so no click or reload lands on a 404.
export function currentRoute() {
  const hash = window.location.hash || "";
  if (hash.startsWith("#/console")) return hash;
  const path = window.location.pathname || "/";
  if (path.startsWith("/console") || path.startsWith("/triage") || path.startsWith("/exposure") || path.startsWith("/access")) {
    return "#/console" + (path.startsWith("/console") ? path.slice("/console".length) : path);
  }
  return hash || "#/";
}

export default function App() {
  const [route, setRoute] = useState(currentRoute());
  useEffect(() => {
    const onHash = () => { setRoute(currentRoute()); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return route.startsWith("#/console") ? <Dashboard /> : <Landing />;
}
