import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// the dashboard calls the backend server through /api
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://localhost:8000" } },
  // neo4j's visualization library is about 1.2 MB; it loads only when the graph tab opens, so the default
  // 500 KB warning does not apply to it
  build: { chunkSizeWarningLimit: 1400 },
});
