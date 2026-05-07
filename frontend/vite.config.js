import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/start-scan": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
        timeout: 2400000,
        proxyTimeout: 2400000,
      },
      "/rag-query": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/scan-history": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/scan-status": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/scan": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/export-md": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
});
