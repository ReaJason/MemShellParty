/**
 * Cross-language codec interop — the test that keeps the TypeScript client
 * (mimic-codecs.ts) and the Java filter (java-template.ts) byte-compatible.
 *
 * For every cipher combo it compiles a CryptoProbe class (the SAME snippets
 * the filter uses) and checks both directions:
 *   TS encrypt -> java decrypt == plaintext
 *   java encrypt -> TS decrypt == plaintext
 *
 * Skipped automatically when no JDK is available.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { md5Key16 } from "../connect/crypto.js";
import {
  CIPHER_ALGORITHMS,
  CIPHER_ENCODINGS,
  decryptField,
  encryptField,
  type MimicCipher,
} from "../connect/mimic-codecs.js";
import { renderCryptoProbe, renderFilterJava, renderWrapperJava } from "./java-template.js";
import { compileJava, hasJavac, servletApiJar } from "./javac.js";

const HAVE_JAVAC = hasJavac();
const SECRET = "probe-key-123";
const AES_KEY = md5Key16(SECRET);
const PLAINTEXTS = [
  Buffer.from("id"),
  Buffer.from("echo 跨语言-interop-$pecial & <chars>", "utf8"),
  Buffer.alloc(0),
];

const COMBOS: MimicCipher[] = CIPHER_ALGORITHMS.flatMap((algorithm) =>
  CIPHER_ENCODINGS.flatMap((encoding) =>
    [false, true].map((padTail) => ({ algorithm, encoding, padTail, marker: "js-var" as const })),
  ),
);

describe.skipIf(!HAVE_JAVAC)("java <-> ts codec interop (javac available)", () => {
  let dir = "";

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mimic-probe-"));
    const sources: string[] = [];
    for (const [i, cipher] of COMBOS.entries()) {
      // one probe class per combo — the class name must match the file name
      const name = `CryptoProbe${i}`;
      const file = join(dir, `${name}.java`);
      writeFileSync(file, renderCryptoProbe(cipher).replaceAll("CryptoProbe", name), "utf8");
      sources.push(file);
    }
    compileJava(sources, dir);
  }, 120_000);

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("the generated filter compiles (mixed placeholder + HTML templates)", () => {
    const pkg = join(dir, "mimic");
    mkdirSync(pkg, { recursive: true });
    // phase 1: the body wrapper (also proves its standalone source compiles)
    const wrapperFile = join(pkg, "CachedBody.java");
    writeFileSync(wrapperFile, renderWrapperJava(), "utf8");
    compileJava([wrapperFile], dir, { classpath: [servletApiJar()] });
    const wrapper = {
      bodyB64: readFileSync(join(pkg, "CachedBody.class")).toString("base64"),
      streamB64: readFileSync(join(pkg, "CachedBody$Stream.class")).toString("base64"),
    };
    // phase 2: the filter with the wrapper bytes embedded
    const java = renderFilterJava({
      className: "CompileCheck",
      pass: "p",
      secret: "k",
      fields: ["verCode", "token"],
      bodyContentTypes: ["json"],
      templates: [
        { template: "<html><body>登录</body></html>", contentType: "text/html;charset=UTF-8" },
        { template: '{"code":0,"data":"{{payload}}"}', contentType: "application/json" },
      ],
      cipher: { algorithm: "aes-cbc", encoding: "base64", padTail: true, marker: "html-comment" },
      wrapper,
    });
    const file = join(pkg, "CompileCheck.java");
    writeFileSync(file, java, "utf8");
    // throws on any javac error — the servlet API jar covers Filter/wrapper types
    compileJava([file], dir, { classpath: [servletApiJar()] });
  });

  function javaProbe(index: number, mode: "enc" | "dec", value: string): string {
    return execFileSync("java", ["-cp", dir, `CryptoProbe${index}`, mode, SECRET, value], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    }).trim();
  }

  for (const [index, cipher] of COMBOS.entries()) {
    const label = `${cipher.algorithm}/${cipher.encoding}/padTail=${cipher.padTail}`;
    it(`java decrypts TS ciphertext (${label})`, () => {
      for (const plain of PLAINTEXTS) {
        const wire = encryptField(plain, AES_KEY, cipher);
        expect(javaProbe(index, "dec", wire)).toBe(plain.toString("hex"));
      }
    });
    it(`TS decrypts java ciphertext (${label})`, () => {
      for (const plain of PLAINTEXTS) {
        const wire = javaProbe(index, "enc", plain.toString("hex"));
        expect(decryptField(wire, AES_KEY, cipher).equals(plain)).toBe(true);
      }
    });
  }
});
