/**
 * Crypto helpers shared by the webshell connection testers.
 *
 * All three tools (Behinder / Godzilla) use AES/ECB/PKCS5Padding with a
 * 16-byte key derived from an MD5 hex string — exactly what Java's
 * `Cipher.getInstance("AES")` does. Node's `aes-128-ecb` with automatic
 * padding is wire-compatible with that.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";

/** Lowercase 32-char hex MD5, same as Java `functions.byteArrayToHex(md5(...))`. */
export function md5Hex(data: string | Buffer): string {
  return createHash("md5").update(data).digest("hex");
}

/** md5 hex truncated to 16 chars — the AES key derivation used by both tools. */
export function md5Key16(data: string): string {
  return md5Hex(data).slice(0, 16);
}

/** AES/ECB/PKCS5Padding encrypt. `key` is used as raw UTF-8 bytes (16 chars). */
export function aesEcbEncrypt(data: Buffer, key: string): Buffer {
  const cipher = createCipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/** AES/ECB/PKCS5Padding decrypt. Throws on bad padding (wrong key / garbage). */
export function aesEcbDecrypt(data: Buffer, key: string): Buffer {
  const decipher = createDecipheriv("aes-128-ecb", Buffer.from(key, "utf8"), null);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

export function gzip(data: Buffer): Buffer {
  return gzipSync(data);
}

/**
 * Godzilla's `functions.gzipD` behaviour: on gunzip failure it falls back to
 * the raw bytes when the input is small (< 200 bytes), otherwise it throws.
 */
export function gunzipLenient(data: Buffer): Buffer {
  if (data.length === 0) return data;
  try {
    return gunzipSync(data);
  } catch (err) {
    if (data.length < 200) return data;
    throw err;
  }
}

/** Base64url without padding (Java `Base64.getUrlEncoder().withoutPadding()`). */
export function base64UrlEncode(data: Buffer): string {
  return data
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function base64UrlDecode(text: string): Buffer {
  let s = text.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4 !== 0) s += "=";
  return Buffer.from(s, "base64");
}

const RANDOM_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/** Random alphanumeric string, mirroring the tools' `getRandomString`. */
export function randomString(length: number): string {
  const raw = randomBytes(length);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += RANDOM_ALPHABET[raw[i]! % RANDOM_ALPHABET.length];
  }
  return out;
}
