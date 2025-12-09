import { env } from "node:process";
import { reactRouter } from "@react-router/dev/vite";
import tailwindcss from "@tailwindcss/vite";
import mdx from "fumadocs-mdx/vite";
import { defineConfig } from "vite";
import devtoolsJson from "vite-plugin-devtools-json";
import tsconfigPaths from "vite-tsconfig-paths";
import * as MdxConfig from "./source.config";

export default defineConfig({
  base: env.NODE_ENV === "development" ? "/" : `${env.VITE_APP_API_URL}/`,
  plugins: [
    mdx(MdxConfig),
    tailwindcss(),
    reactRouter(),
    devtoolsJson(),
    tsconfigPaths({
      root: __dirname,
    }),
  ],
  resolve:
    process.env.NODE_ENV === "development"
      ? {}
      : {
          alias: {
            "react-dom/server": "react-dom/server.node",
          },
        },
});
