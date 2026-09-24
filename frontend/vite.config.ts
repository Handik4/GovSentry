import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // The SDK chunk (viem + genlayer-js) is ~610 kB minified / ~130 kB gzip on
    // its own; it is split out deliberately, so warn only above that.
    chunkSizeWarningLimit: 700,
    // genlayer-js pulls in viem; keep it in its own chunk so the app shell
    // stays small and the SDK caches independently across deploys.
    rollupOptions: {
      output: {
        manualChunks: (id) => (id.includes("node_modules/genlayer-js") || id.includes("node_modules/viem") ? "genlayer" : undefined),
      },
    },
  },
});
