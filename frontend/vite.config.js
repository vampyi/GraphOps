import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// the dashboard calls the backend server through /api. API=https://graph-ops.vercel.app npm run dev previews the
// frontend against the live site's data (aura) with no database or keys on this machine
const api = process.env.API || "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": { target: api, changeOrigin: true } } },
  // neo4j's visualization library is about 1.2 MB; it loads only when the graph tab opens, so the default
  // 500 KB warning does not apply to it
  build: { chunkSizeWarningLimit: 1400 },
});
