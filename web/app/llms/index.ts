import { llms } from "fumadocs-core/source";

import { source } from "@/lib/source";

export function loader() {
  return new Response(llms(source).index());
}
