import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { MemShellGenerateRequest, MemShellGenerateResponse } from "../api/index.js";
import { LEGACY_CIPHER } from "../connect/mimic-codecs.js";
import type { SiteProfile } from "../core/site-profile.js";
import {
  buildCustomMemshell,
  defaultClassName,
  profileSecretFields,
  type GenerateClient,
} from "./build.js";

const profile: SiteProfile = {
  name: "unit",
  site: "http://127.0.0.1",
  createdAt: new Date().toISOString(),
  templates: [{ title: "t", template: "<html><body>cover</body></html>", contentType: "text/html" }],
  paths: [],
  request: [{ secretField: "verCode" }, { secretField: "X-Token", secretIn: "header" }],
};

function fakeClient(captured: { req?: MemShellGenerateRequest }): GenerateClient {
  return {
    async generateMemShell(req: MemShellGenerateRequest): Promise<MemShellGenerateResponse> {
      captured.req = req;
      return {
        memShellResult: {
          shellClassName: req.shellToolConfig.shellClassName!,
          shellSize: 100,
          shellBytesBase64Str: "AA==",
          injectorClassName: "com.example.Injector1",
          injectorSize: 200,
          injectorBytesBase64Str: "AA==",
          shellConfig: req.shellConfig,
          shellToolConfig: req.shellToolConfig,
          injectorConfig: req.injectorConfig,
        },
        packResult: "UEFZTE9BRA==",
      };
    },
  };
}

/** Stub javac: drop a fake .class next to the .java source (plus the wrapper's stream class). */
function stubCompile(sources: string[]): void {
  for (const src of sources) {
    writeFileSync(src.replace(/\.java$/, ".class"), Buffer.from("CAFEBABE-fake-class"));
    if (src.endsWith("CachedBody.java")) {
      writeFileSync(src.replace(/\.java$/, "$Stream.class"), Buffer.from("CAFEBABE-fake-stream"));
    }
  }
}

describe("profileSecretFields", () => {
  it("collects the unique carrier fields from all request shapes", () => {
    expect(profileSecretFields(profile)).toEqual(["verCode", "X-Token"]);
  });

  it("falls back to 'pass' without request shapes", () => {
    expect(profileSecretFields({ ...profile, request: undefined })).toEqual(["pass"]);
  });
});

describe("defaultClassName", () => {
  it("is a valid Java identifier with a random suffix", () => {
    expect(defaultClassName()).toMatch(/^MimicFilter[A-Za-z0-9]{4}$/);
    expect(defaultClassName()).not.toBe(defaultClassName());
  });
});

describe("buildCustomMemshell", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "memparty-build-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("renders, compiles and submits a Custom generate request", async () => {
    const captured: { req?: MemShellGenerateRequest } = {};
    const result = await buildCustomMemshell(
      { profile, server: "TongWeb", pass: "p1", secret: "k1", outDir: dir },
      fakeClient(captured),
      { compile: stubCompile, servletJar: () => "unused.jar" },
    );

    const req = captured.req!;
    expect(req.shellConfig).toMatchObject({
      server: "TongWeb",
      shellTool: "Custom",
      shellType: "Filter",
      targetJreVersion: 52,
    });
    expect(req.shellToolConfig.shellClassName).toBe(result.fullClassName);
    expect(req.shellToolConfig.shellClassName).toMatch(/^mimic\.MimicFilter[A-Za-z0-9]{4}$/);
    expect(req.shellToolConfig.shellClassBase64).toBe(
      Buffer.from("CAFEBABE-fake-class").toString("base64"),
    );
    expect(req.injectorConfig).toEqual({ urlPattern: "/*" });
    expect(req.packer).toBe("DefaultBase64");

    // the generated java carries the credentials, fields and legacy defaults
    const java = readFileSync(result.files.java, "utf8");
    expect(java).toContain('PASS = "p1"');
    expect(java).toContain('SECRET = "k1"');
    expect(java).toContain('"verCode", "X-Token"');
    expect(java).toContain("AES/ECB");
    expect(result.cipher).toEqual(LEGACY_CIPHER);

    // artifacts: payload + manifest with everything connect needs
    expect(readFileSync(result.files.payloads.DefaultBase64!, "utf8")).toBe("UEFZTE9BRA==\n");
    const manifest = JSON.parse(readFileSync(result.files.manifest, "utf8"));
    expect(manifest).toMatchObject({
      tool: "mimic",
      profile: "unit",
      server: "TongWeb",
      pass: "p1",
      key: "k1",
      className: result.fullClassName,
      injectorClassName: "com.example.Injector1",
    });
    expect(manifest.connect).toContain("--profile unit --pass p1 --key k1");
  });

  it("bakes the profile's cipher selection into filter and manifest", async () => {
    const captured: { req?: MemShellGenerateRequest } = {};
    const cbcProfile: SiteProfile = {
      ...profile,
      cipher: { algorithm: "aes-cbc", encoding: "hex", padTail: true, marker: "html-comment" },
    };
    const result = await buildCustomMemshell(
      { profile: cbcProfile, server: "Tomcat", pass: "p", secret: "k", outDir: dir, className: "MimicFilterZ9" },
      fakeClient(captured),
      { compile: stubCompile, servletJar: () => "unused.jar" },
    );
    const java = readFileSync(result.files.java, "utf8");
    expect(java).toContain("AES/CBC");
    expect(java).toContain("appendPad(s, aesKey)");
    expect(java).toContain("<!--Re");
    expect(result.cipher).toEqual({
      algorithm: "aes-cbc",
      encoding: "hex",
      padTail: true,
      marker: "html-comment",
    });
    const manifest = JSON.parse(readFileSync(result.files.manifest, "utf8"));
    expect(manifest.cipher.algorithm).toBe("aes-cbc");
    expect(manifest.className).toBe("mimic.MimicFilterZ9");
  });

  it("writes one payload file per variant for aggregate packers", async () => {
    const client: GenerateClient = {
      async generateMemShell(req: MemShellGenerateRequest): Promise<MemShellGenerateResponse> {
        return {
          memShellResult: {
            shellClassName: req.shellToolConfig.shellClassName!,
            shellSize: 1,
            shellBytesBase64Str: "AA==",
            injectorClassName: "x.Injector",
            injectorSize: 1,
            injectorBytesBase64Str: "AA==",
            shellConfig: req.shellConfig,
            shellToolConfig: req.shellToolConfig,
            injectorConfig: req.injectorConfig,
          },
          allPackResults: { DefaultBase64: "QQ==", GzipBase64: "Qg==" },
        };
      },
    };
    const result = await buildCustomMemshell(
      { profile, server: "Tomcat", pass: "p", secret: "k", outDir: dir, packer: "Base64" },
      client,
      { compile: stubCompile, servletJar: () => "unused.jar" },
    );
    expect(Object.keys(result.files.payloads).sort()).toEqual(["DefaultBase64", "GzipBase64"]);
    expect(readFileSync(result.files.payloads.GzipBase64!, "utf8")).toBe("Qg==\n");
  });
});
