import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the backend through this proxy, so the browser sees a single address
// and the refresh cookie and WebSocket work without any CORS settings on the backend.
// The backend itself can stay on 127.0.0.1: only the dashboard is reachable from the network.
const BACKEND = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // listen on every network address, not only localhost
    port: 5173,
    proxy: {
      "/api": { target: BACKEND, ws: true },
      "/health": BACKEND,
    },
  },
});
