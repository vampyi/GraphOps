import { useEffect, useState } from "react";
import Landing from "./Landing.jsx";
import Dashboard from "./Dashboard.jsx";

// two screens: the landing page (#/) and the console (#/console)
export default function App() {
  const [route, setRoute] = useState(window.location.hash || "#/");
  useEffect(() => {
    const onHash = () => { setRoute(window.location.hash || "#/"); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return route.startsWith("#/console") ? <Dashboard /> : <Landing />;
}
