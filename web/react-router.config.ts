import type { Config } from "@react-router/dev/config";

import { createGetUrl, getSlugs } from "fumadocs-core/source";
import { glob } from "node:fs/promises";
import { env } from "node:process";

const getUrl = createGetUrl("/docs");

export default {
  basename: env.VITE_APP_BASE_PATH,
  ssr: false,
  future: {
    v8_middleware: true,
  },
  async prerender({ getStaticPaths }) {
    const paths: string[] = [];
    const excluded: string[] = [];

    for (const path of getStaticPaths()) {
      if (!excluded.includes(path)) paths.push(path);
    }

    for await (const entry of glob("**/*.mdx", { cwd: "content/docs" })) {
      const slugs = getSlugs(entry);
      paths.push(getUrl(slugs), `/llms.mdx/docs/${[...slugs, "content.md"].join("/")}`);
    }

    return paths;
  },
} satisfies Config;
