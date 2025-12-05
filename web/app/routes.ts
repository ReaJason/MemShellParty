import { index, type RouteConfig, route } from "@react-router/dev/routes";

export default [
  index("routes/memshell.tsx", {
    id: "index-memshell",
  }),
  route("docs/*", "docs/page.tsx"),
  route("api/search", "docs/search.ts"),
  route("about", "routes/about.tsx"),
  route("memshell", "routes/memshell.tsx"),
  route("probeshell", "routes/probeshell.tsx"),
] satisfies RouteConfig;
