import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { cp } from "node:fs/promises";
import { join, resolve } from "node:path";

const BASE_DIR = resolve("../boot/src/main/resources");
const STATIC_DIR = join(BASE_DIR, "static");
const ASSETS_DIR = join(STATIC_DIR, "assets");
const TEMPLATES_DIR = join(BASE_DIR, "templates");
const SRC_DIR = resolve("dist");

async function main() {
  console.log("Copy assets into SpringBoot resources");

  if (!existsSync(SRC_DIR)) {
    console.error(`Error: ${SRC_DIR} does not exist`);
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
    if (existsSync(join(SRC_DIR, "vite.svg"))) {
      await cp(join(SRC_DIR, "vite.svg"), join(STATIC_DIR, "vite.svg"));
    }

    const assetsSourceDir = join(SRC_DIR, "assets");
    if (existsSync(assetsSourceDir)) {
      await cp(assetsSourceDir, ASSETS_DIR, { recursive: true });
    }
  } catch (err) {
    console.error("Error copying assets:", err);
    process.exit(1);
  }

  const INDEX_SRC = join(SRC_DIR, "index.html");
  const INDEX_DEST = join(TEMPLATES_DIR, "index.html");

  if (!existsSync(INDEX_SRC)) {
    console.error(`Error: ${INDEX_SRC} does not exist. Make sure you built the frontend project first.`);
    process.exit(1);
  }

  const htmlContent = readFileSync(INDEX_SRC, "utf8");
  const updatedHtml = htmlContent
    .replace(/href="([^"]*)"/g, 'th:href="@{$1}"')
    .replace(/src="([^"]*)"/g, 'th:src="@{$1}"');

  writeFileSync(INDEX_DEST, updatedHtml);
  console.log("SpringBoot resources updated successfully");
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
