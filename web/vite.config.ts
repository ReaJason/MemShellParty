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
    // React Router 8 prerendering requests the Vite preview server over HTTP.
    // Bind it explicitly to IPv4 so `localhost` resolves to the address being listened on in Docker.
    preview: { host: "127.0.0.1" },
    base: isDev || !contextPath ? "/" : `${contextPath}/`,
    plugins: [fumadocsMdx(), tailwindcss(), reactRouter(), devtoolsJson()],
    resolve: {
      tsconfigPaths: true,
      alias: !isDev ? { "react-dom/server": "react-dom/server.node" } : {},
    },
  };
});
