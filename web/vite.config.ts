import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          highlight: ["react-syntax-highlighter"],
          radixUi: ["radix-ui"],
          motion: ["framer-motion", "motion"],
          sonner: ["sonner"],
          yup: ["yup"],
          i18n: ["react-i18next", "i18next"],
          reactRouter: ["react-router", "react-router-dom"],
        },
      },
    },
  },
});
