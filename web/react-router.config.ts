import { glob } from "node:fs/promises";
import { env } from "node:process";
import type { Config } from "@react-router/dev/config";
import { createGetUrl, getSlugs } from "fumadocs-core/source";

const getUrl = createGetUrl("/docs");

export default {
  basename: env.VITE_APP_BASE_PATH,
  ssr: false,
  async prerender({ getStaticPaths }) {
    const paths: string[] = [];
    const excluded: string[] = [];
    for (const path of getStaticPaths()) {
      if (!excluded.includes(path)) paths.push(path);
    }
    for await (const entry of glob("**/*.mdx", { cwd: "content/docs" })) {
      paths.push(getUrl(getSlugs(entry)));
    }
    return paths;
  },
} satisfies Config;
