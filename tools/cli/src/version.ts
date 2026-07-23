import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

interface PkgJson {
  version: string;
}

// package.json sits one level above the built dist/ file and above src/ in dev.
let version = "0.0.0";
try {
  version = (require("../package.json") as PkgJson).version;
} catch {
  try {
    version = (require("./package.json") as PkgJson).version;
  } catch {
    // fall back to placeholder
  }
}

export const CLI_VERSION = version;
