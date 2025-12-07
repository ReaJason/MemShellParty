import { existsSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { cp } from "node:fs/promises";
import { join, resolve } from "node:path";

const BASE_DIR = resolve("../boot/src/main/resources");
const STATIC_DIR = join(BASE_DIR, "static");
const ASSETS_DIR = join(STATIC_DIR, "assets");
const TEMPLATES_DIR = join(BASE_DIR, "templates");
const BUILD_DIR = resolve("build/client");
const BUILD_ASSERTS_DIR = join(BUILD_DIR, "assets");

function findUiDirectory(baseDir, maxDepth = 5) {
  function search(currentDir, depth) {
    if (depth > maxDepth) return null;

    const entries = readdirSync(currentDir);

    for (const entry of entries) {
      const fullPath = join(currentDir, entry);

      if (!statSync(fullPath).isDirectory()) continue;

      if (entry === "ui") {
        return fullPath;
      }

      const found = search(fullPath, depth + 1);
      if (found) return found;
    }

    return null;
  }

  return search(baseDir, 0);
}

async function main() {
  if (!existsSync(BUILD_DIR)) {
    console.error(`Error: ${BUILD_DIR} does not exist`);
    process.exit(1);
  }

  mkdirSync(ASSETS_DIR, { recursive: true });
  mkdirSync(TEMPLATES_DIR, { recursive: true });

  if (existsSync(ASSETS_DIR)) {
    const files = readdirSync(ASSETS_DIR);
    for (const file of files) {
      rmSync(join(ASSETS_DIR, file), { recursive: true, force: true });
    }
  }

  try {
    await cp(join(BUILD_DIR, "favicon.ico"), join(STATIC_DIR, "favicon.ico"));
    await cp(BUILD_ASSERTS_DIR, ASSETS_DIR, { recursive: true });
  } catch (err) {
    console.error("Error copying assets:", err);
    process.exit(1);
  }

  const uiDir = findUiDirectory(BUILD_DIR);
  if (!uiDir) {
    console.error(`Error: ui directory not found in ${BUILD_DIR}`);
    process.exit(1);
  }
  await cp(uiDir, join(TEMPLATES_DIR), { recursive: true });
  console.log("SpringBoot resources updated successfully");
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
