import { describe, expect, it } from "vitest";

import { aesEcbEncrypt, md5Key16 } from "./crypto.js";
import {
  CIPHER_ALGORITHMS,
  CIPHER_ENCODINGS,
  LEGACY_CIPHER,
  decryptField,
  deriveMarkers,
  encryptField,
  padTailLength,
  resolveCipher,
  type MimicCipher,
} from "./mimic-codecs.js";

const key = md5Key16("key");
const plain = Buffer.from("echo hello-mimic-世界-$pecial", "utf8");

const ALL_COMBOS: MimicCipher[] = CIPHER_ALGORITHMS.flatMap((algorithm) =>
  CIPHER_ENCODINGS.flatMap((encoding) =>
    [false, true].map((padTail) => ({ algorithm, encoding, padTail, marker: "js-var" as const })),
  ),
);

describe("mimic codecs", () => {
  it("legacy cipher is byte-identical to the original wire format", () => {
    expect(encryptField(plain, key)).toBe(aesEcbEncrypt(plain, key).toString("base64"));
    expect(decryptField(encryptField(plain, key), key).equals(plain)).toBe(true);
  });

  it("resolveCipher fills the legacy defaults", () => {
    expect(resolveCipher()).toEqual(LEGACY_CIPHER);
    expect(resolveCipher({ algorithm: "xor" })).toEqual({ ...LEGACY_CIPHER, algorithm: "xor" });
    expect(resolveCipher(undefined)).toEqual(LEGACY_CIPHER);
  });

  for (const cipher of ALL_COMBOS) {
    it(`round-trips ${cipher.algorithm}/${cipher.encoding}/padTail=${cipher.padTail}`, () => {
      const wire = encryptField(plain, key, cipher);
      expect(decryptField(wire, key, cipher).equals(plain)).toBe(true);
      // and the empty payload edge case (heartbeat-style empty output)
      const empty = Buffer.alloc(0);
      expect(decryptField(encryptField(empty, key, cipher), key, cipher).equals(empty)).toBe(true);
    });
  }

  it("aes-cbc produces different bytes for the same plaintext (random IV)", () => {
    const cipher: MimicCipher = { ...LEGACY_CIPHER, algorithm: "aes-cbc" };
    expect(encryptField(plain, key, cipher)).not.toBe(encryptField(plain, key, cipher));
  });

  it("padTail appends key-derived-length alnum garbage after encoding", () => {
    const cipher: MimicCipher = { ...LEGACY_CIPHER, padTail: true };
    const unpadded = encryptField(plain, key, LEGACY_CIPHER);
    const padded = encryptField(plain, key, cipher);
    const n = padTailLength(key);
    expect(padded.length).toBe(unpadded.length + n);
    expect(padded.slice(0, unpadded.length)).toBe(unpadded);
    expect(padded.slice(unpadded.length)).toMatch(/^[A-Za-z0-9]*$/);
  });

  it("padTailLength is deterministic from the key and within 0-15", () => {
    expect(padTailLength(key)).toBe(padTailLength(key));
    expect(padTailLength(key)).toBeGreaterThanOrEqual(0);
    expect(padTailLength(key)).toBeLessThan(16);
    expect(padTailLength(md5Key16("other"))).not.toBe(padTailLength(md5Key16("yet-another")));
  });

  it("derives per-shell markers in both styles", () => {
    const legacy = deriveMarkers("pass", "key");
    expect(legacy.left).toMatch(/^var Re[0-9a-f]{5}_config="$/);
    expect(legacy.right).toBe('";');
    expect(legacy.wrap("PAYLOAD")).toBe(`<script>${legacy.left}PAYLOAD";</script>`);
    expect(deriveMarkers("other", "key").left).not.toBe(legacy.left);

    const comment = deriveMarkers("pass", "key", { ...LEGACY_CIPHER, marker: "html-comment" });
    expect(comment.left).toMatch(/^<!--Re[0-9a-f]{5}_config:$/);
    expect(comment.right).toBe("-->");
    expect(comment.wrap("PAYLOAD")).toBe(`${comment.left}PAYLOAD-->`);
    // both styles share the same per-shell id
    expect(comment.left).toContain(legacy.left.slice(6, 11));
  });

  it("decryptField with a wrong key never yields the plaintext", () => {
    // AES wrong-key decrypt usually throws on bad padding — but ~1/256 of keys
    // "succeed" with garbage output. The guarantee the server relies on:
    // a wrong key never produces the real plaintext.
    for (const wrong of ["wrong", "wrong2", "wrong3", "wrong4"]) {
      try {
        const out = decryptField(encryptField(plain, key), md5Key16(wrong));
        expect(out.equals(plain)).toBe(false);
      } catch {
        // bad padding — the common case, equally fine
      }
    }
  });
});
