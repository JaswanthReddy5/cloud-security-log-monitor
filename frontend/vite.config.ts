import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development, /api requests are proxied to the local Flask server.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: process.env.VITE_DEV_API ?? "http://127.0.0.1:5000", changeOrigin: true },
    },
  },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900 },
});
