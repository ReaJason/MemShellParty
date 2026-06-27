import { reactRouter } from "@react-router/dev/vite";
import tailwindcss from "@tailwindcss/vite";
import mdx from "fumadocs-mdx/vite";
import path from "node:path";
import { defineConfig, loadEnv } from "vite";
import devtoolsJson from "vite-plugin-devtools-json";

import * as MdxConfig from "./source.config";

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_APP_");
  const isDev = command === "serve";
  const contextPath = env.VITE_APP_API_URL?.trim() ?? "";

  return {
    base: isDev || !contextPath ? "/" : `${contextPath}/`,
    plugins: [mdx(MdxConfig), tailwindcss(), reactRouter(), devtoolsJson()],
    resolve: {
      tsconfigPaths: true,
      alias: {
        "@": path.resolve(__dirname, "./app"),
        ...(!isDev
          ? {
              "react-dom/server": "react-dom/server.node",
            }
          : {}),
      },
    },
  };
});
