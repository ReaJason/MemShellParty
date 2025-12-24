import path from "node:path";
import { env } from "node:process";
import { reactRouter } from "@react-router/dev/vite";
import tailwindcss from "@tailwindcss/vite";
import mdx from "fumadocs-mdx/vite";
import { defineConfig } from "vite";
import devtoolsJson from "vite-plugin-devtools-json";
import tsconfigPaths from "vite-tsconfig-paths";
import * as MdxConfig from "./source.config";

const isDev = env.NODE_ENV === "development";
export default defineConfig({
  base: isDev ? "/" : `${env.VITE_APP_API_URL}/`,
  plugins: [
    mdx(MdxConfig),
    tailwindcss(),
    reactRouter(),
    devtoolsJson(),
    tsconfigPaths({
      root: __dirname,
    }),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./app"),
      ...(!isDev
        ? {
            "react-dom/server": "react-dom/server.node",
          }
        : {}),
    },
  },
});
