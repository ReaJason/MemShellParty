import { reactRouter } from "@react-router/dev/vite";
import tailwindcss from "@tailwindcss/vite";
import { fumadocsMdx } from "fumadocs-mdx/vite";
import { defineConfig, loadEnv } from "vite";
import devtoolsJson from "vite-plugin-devtools-json";

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_APP_");
  const isDev = command === "serve";
  const contextPath = env.VITE_APP_API_URL?.trim() ?? "";

  return {
    base: isDev || !contextPath ? "/" : `${contextPath}/`,
    plugins: [fumadocsMdx(), tailwindcss(), reactRouter(), devtoolsJson()],
    resolve: {
      tsconfigPaths: true,
      alias: !isDev ? { "react-dom/server": "react-dom/server.node" } : {},
    },
  };
});
