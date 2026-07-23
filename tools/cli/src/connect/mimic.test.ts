import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { ResolvedConnection } from "../core/targets.js";
import { saveProfile, type SiteProfile } from "../core/site-profile.js";
import { startMimicServer, type MimicServer } from "./mimic-server.js";
import {
  deriveAesKey,
  deriveLeftMarker,
  encodeRequestBody,
  encryptField,
  extractBetween,
  injectIntoTemplate,
  decryptField,
  decodeAnyBody,
  decodeMultipartBody,
  decodeXmlBody,
  renderBodyTemplate,
  renderFieldValue,
  templateDelimiters,
} from "./mimic-shared.js";
import { mimicProtocol } from "./mimic.js";
import type { ProtocolRequest } from "./registry.js";

let server: MimicServer;
let dir: string;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "memparty-profiles-"));
  process.env.MEMPARTY_PROFILES = dir;
  server = await startMimicServer();
});

afterEach(async () => {
  delete process.env.MEMPARTY_PROFILES;
  rmSync(dir, { recursive: true, force: true });
  await server.close();
});

function makeRequest(overrides: Partial<ProtocolRequest["options"]> = {}): ProtocolRequest {
  const conn: ResolvedConnection = {
    url: server.url,
    tool: "mimic",
    pass: "pass",
    key: "key",
    extraHeaders: {},
  };
  return {
    conn,
    common: { timeoutMs: 5_000 },
    options: overrides,
  };
}

const demoProfile: SiteProfile = {
  name: "unit",
  site: "http://127.0.0.1",
  createdAt: new Date().toISOString(),
  title: "unit test site",
  template: "<html><body>skin</body></html>",
  contentType: "text/html",
  paths: ["/api/", "/news/"],
};

describe("mimic protocol", () => {
  it("test() does a credential round-trip", async () => {
    const result = await mimicProtocol.test(makeRequest());
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("round-trip ok");
  });

  it("exec() runs a command and returns its output", async () => {
    const result = await mimicProtocol.exec!(makeRequest(), "echo mimic-canary-123");
    expect(result.ok).toBe(true);
    expect(result.output).toContain("mimic-canary-123");
  });

  it("fails with a wrong key", async () => {
    const req = makeRequest();
    req.conn = { ...req.conn, key: "wrong" };
    const result = await mimicProtocol.test(req);
    expect(result.ok).toBe(false);
  });

  it("uses a dynamic path from the profile when enabled", async () => {
    saveProfile(demoProfile);
    const result = await mimicProtocol.test(
      makeRequest({ profile: "unit", dynamicPath: true }),
    );
    expect(result.ok).toBe(true);
    expect(result.detail).toContain("dynamic path");
    expect(result.detail).toMatch(/\/(api|news)\//);
  });

  it("errors clearly when the profile does not exist", async () => {
    const result = await mimicProtocol.test(makeRequest({ profile: "nope" }));
    expect(result.ok).toBe(false);
    expect(result.error).toContain("unknown profile");
  });

  it("carries the ciphertext in the URL query when secretIn=query", async () => {
    saveProfile({
      ...demoProfile,
      name: "q",
      request: {
        secretField: "pass",
        secretIn: "query",
        fields: [{ name: "locale", value: "zh_CN" }],
      },
    });
    const result = await mimicProtocol.test(makeRequest({ profile: "q" }));
    expect(result.ok).toBe(true);
  });

  it("carries the ciphertext in a header when secretIn=header", async () => {
    saveProfile({
      ...demoProfile,
      name: "h",
      request: {
        secretField: "pass",
        secretIn: "header",
        fields: [{ name: "csrftoken", value: "{{hex:16}}" }],
      },
    });
    const result = await mimicProtocol.test(makeRequest({ profile: "h" }));
    expect(result.ok).toBe(true);
  });

  it("accepts an array of request shapes and rotates", async () => {
    saveProfile({
      ...demoProfile,
      name: "rot",
      request: [
        { secretField: "pass", fields: [] },
        { secretField: "pass", secretIn: "query", fields: [] },
        { secretField: "pass", secretIn: "header", fields: [] },
      ],
    });
    // three modes x a few runs — all must round-trip whichever shape was picked
    for (let i = 0; i < 6; i++) {
      const result = await mimicProtocol.test(makeRequest({ profile: "rot" }));
      expect(result.ok).toBe(true);
    }
  });

  it("round-trips with aes-cbc + padTail + html-comment markers", async () => {
    await server.close();
    server = await startMimicServer({
      cipher: { algorithm: "aes-cbc", encoding: "base64", padTail: true, marker: "html-comment" },
    });
    saveProfile({
      ...demoProfile,
      name: "cbc",
      cipher: { algorithm: "aes-cbc", encoding: "base64", padTail: true, marker: "html-comment" },
    });
    const test = await mimicProtocol.test(makeRequest({ profile: "cbc" }));
    expect(test.ok).toBe(true);
    const exec = await mimicProtocol.exec!(makeRequest({ profile: "cbc" }), "echo cbc-canary-7");
    expect(exec.ok).toBe(true);
    expect(exec.output).toContain("cbc-canary-7");
  });

  it("round-trips with xor + hex encoding", async () => {
    await server.close();
    server = await startMimicServer({ cipher: { algorithm: "xor", encoding: "hex" } });
    saveProfile({ ...demoProfile, name: "xor", cipher: { algorithm: "xor", encoding: "hex" } });
    const result = await mimicProtocol.test(makeRequest({ profile: "xor" }));
    expect(result.ok).toBe(true);
  });

  it("round-trips a JSON body through a JSON placeholder skin", async () => {
    const apiSkin = '{"code":0,"msg":"ok","data":"{{payload}}","ts":1712345678}';
    await server.close();
    server = await startMimicServer({
      templates: [{ title: "api", template: apiSkin, contentType: "application/json;charset=utf-8" }],
      fields: ["token"],
    });
    saveProfile({
      ...demoProfile,
      name: "json",
      templates: [{ title: "api", template: apiSkin, contentType: "application/json;charset=utf-8" }],
      request: {
        secretField: "token",
        bodyStyle: "json",
        fields: [
          { name: "username", value: "admin" },
          { name: "nonce", value: "{{hex:16}}" },
        ],
        headers: { Accept: "application/json, text/plain, */*" },
      },
    });
    const test = await mimicProtocol.test(makeRequest({ profile: "json" }));
    expect(test.ok).toBe(true);
    const exec = await mimicProtocol.exec!(makeRequest({ profile: "json" }), "echo json-canary-9");
    expect(exec.ok).toBe(true);
    expect(exec.output).toContain("json-canary-9");
  });

  it("round-trips an OpenAI-style chat body through an SSE skin", async () => {
    const sseSkin =
      'data: {"id":"chatcmpl-9","object":"chat.completion.chunk","choices":[{"delta":{"content":"{{payload}}"}}]}\n\ndata: [DONE]\n\n';
    await server.close();
    server = await startMimicServer({
      templates: [{ title: "sse", template: sseSkin, contentType: "text/event-stream" }],
      fields: ["content"],
    });
    saveProfile({
      ...demoProfile,
      name: "chat",
      templates: [{ title: "sse", template: sseSkin, contentType: "text/event-stream" }],
      request: {
        secretField: "content",
        bodyTemplate:
          '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"{{payload}}"}]}',
        headers: { Accept: "text/event-stream", Authorization: "Bearer sk-test" },
      },
    });
    const test = await mimicProtocol.test(makeRequest({ profile: "chat" }));
    expect(test.ok).toBe(true);
    const exec = await mimicProtocol.exec!(makeRequest({ profile: "chat" }), "echo sse-canary-7");
    expect(exec.ok).toBe(true);
    expect(exec.output).toContain("sse-canary-7");
  });

  it("round-trips a GraphQL mutation body", async () => {
    const gqlSkin = '{"data":{"run":{"ok":true,"out":"{{payload}}"}}}';
    await server.close();
    server = await startMimicServer({
      templates: [{ title: "gql", template: gqlSkin, contentType: "application/json" }],
      fields: ["variables"],
    });
    saveProfile({
      ...demoProfile,
      name: "gql",
      templates: [{ title: "gql", template: gqlSkin, contentType: "application/json" }],
      request: {
        secretField: "variables",
        bodyTemplate:
          '{"operationName":"Run","query":"mutation Run{run}","variables":"{{payload}}","nonce":"{{hex:8}}"}',
      },
    });
    const result = await mimicProtocol.exec!(makeRequest({ profile: "gql" }), "echo gql-canary-5");
    expect(result.ok).toBe(true);
    expect(result.output).toContain("gql-canary-5");
  });

  it("round-trips an XML SOAP body through an XML skin", async () => {
    const xmlSkin = '<?xml version="1.0"?><response><code>0</code><data>{{payload}}</data></response>';
    await server.close();
    server = await startMimicServer({
      templates: [{ title: "xml", template: xmlSkin, contentType: "text/xml" }],
      fields: ["token"],
    });
    saveProfile({
      ...demoProfile,
      name: "soap",
      templates: [{ title: "xml", template: xmlSkin, contentType: "text/xml" }],
      request: {
        secretField: "token",
        bodyTemplate:
          '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><exec><token>{{payload}}</token><ts>{{ts}}</ts></exec></soap:Body></soap:Envelope>',
      },
    });
    const result = await mimicProtocol.exec!(makeRequest({ profile: "soap" }), "echo xml-canary-3");
    expect(result.ok).toBe(true);
    expect(result.output).toContain("xml-canary-3");
  });

  it("round-trips a multipart/form-data upload body", async () => {
    const uploadBody = [
      "------MempartyForm7x",
      'Content-Disposition: form-data; name="file"; filename="avatar.png"',
      "Content-Type: image/png",
      "",
      "{{b64:48}}",
      "------MempartyForm7x",
      'Content-Disposition: form-data; name="desc"',
      "",
      "{{payload}}",
      "------MempartyForm7x--",
      "",
    ].join("\r\n");
    await server.close();
    server = await startMimicServer({ fields: ["desc"] });
    saveProfile({
      ...demoProfile,
      name: "upload",
      request: { secretField: "desc", bodyTemplate: uploadBody },
    });
    const result = await mimicProtocol.exec!(makeRequest({ profile: "upload" }), "echo mp-canary-2");
    expect(result.ok).toBe(true);
    expect(result.output).toContain("mp-canary-2");
  });

  it("rotates mixed HTML + JSON-placeholder skins without breaking extraction", async () => {
    const apiSkin = '{"result":"{{payload}}"}';
    await server.close();
    server = await startMimicServer({
      templates: [
        { title: "html", template: "<html><body>portal</body></html>", contentType: "text/html" },
        { title: "api", template: apiSkin, contentType: "application/json" },
      ],
    });
    saveProfile({
      ...demoProfile,
      name: "mixed",
      templates: [
        { title: "html", template: "<html><body>portal</body></html>", contentType: "text/html" },
        { title: "api", template: apiSkin, contentType: "application/json" },
      ],
    });
    // several runs so both skins get exercised (server rotates at random)
    for (let i = 0; i < 8; i++) {
      const result = await mimicProtocol.test(makeRequest({ profile: "mixed" }));
      expect(result.ok).toBe(true);
    }
  });

  it("fails cleanly when client and server ciphers disagree", async () => {
    saveProfile({ ...demoProfile, name: "mismatch", cipher: { algorithm: "aes-cbc" } });
    // server still speaks the legacy default
    const result = await mimicProtocol.test(makeRequest({ profile: "mismatch" }));
    expect(result.ok).toBe(false);
  });
});

describe("mimic-shared wire format", () => {
  it("derives a per-shell left marker", () => {
    expect(deriveLeftMarker("pass", "key")).toMatch(/^var Re[0-9a-f]{5}_config="$/);
    expect(deriveLeftMarker("pass", "key")).not.toBe(deriveLeftMarker("other", "key"));
  });

  it("injects the script before </body> and keeps the page valid", () => {
    const html = "<html><body>skin</body></html>";
    const out = injectIntoTemplate(html, "QUJD", 'var Reabc12_config="');
    expect(out).toBe('<html><body>skin<script>var Reabc12_config="QUJD";</script></body></html>');
  });

  it("builds the form body with decoy fields and renders {{hex:N}}", () => {
    const body = encodeRequestBody("verCode", Buffer.from("id"), deriveAesKey("key"), [
      { name: "csrftoken", value: "{{hex:32}}" },
      { name: "j_username", value: "admin" },
    ]).toString();
    const params = new URLSearchParams(body);
    expect(params.get("csrftoken")).toMatch(/^[0-9a-f]{32}$/);
    expect(params.get("j_username")).toBe("admin");
    expect(params.get("pass")).toBeNull();
    // the ciphertext round-trips through the secret field
    expect(decryptField(params.get("verCode")!, deriveAesKey("key")).toString()).toBe("id");
  });

  it("renders {{hex:N}} deterministically in shape and leaves plain text alone", () => {
    expect(renderFieldValue("{{hex:8}}")).toMatch(/^[0-9a-f]{8}$/);
    expect(renderFieldValue("on")).toBe("on");
    expect(renderFieldValue("a{{hex:4}}b")).toMatch(/^a[0-9a-f]{4}b$/);
  });

  it("computes delimiters per template: placeholder bounds + marker fallback", () => {
    const markers = { left: 'var Reabc12_config="', right: '";' };
    const d = templateDelimiters(
      [
        { template: '{"a":"{{payload}}","b":1}' },
        { template: "<html><body>x</body></html>" },
        { template: "prefix-{{payload}}" },
      ],
      markers,
    );
    expect(d[0]).toEqual({ left: '{"a":"', right: '","b":1}' });
    expect(d[1]).toEqual(markers); // one shared marker pair for HTML templates
    expect(d[2]).toEqual({ left: "prefix-", right: "" });
    expect(templateDelimiters([], markers)).toEqual([markers]);
  });

  it("extractBetween honors an empty right bound as to-end", () => {
    expect(extractBetween('{"a":"CIPHER","b":1}', '{"a":"', '","b":1}')).toBe("CIPHER");
    expect(extractBetween("prefix-CIPHER", "prefix-", "")).toBe("CIPHER");
    expect(extractBetween("nothing here", "prefix-", "")).toBeNull();
  });

  it("renderBodyTemplate substitutes payload and renders decoy macros", () => {
    const out = renderBodyTemplate(
      '{"a":"{{payload}}","n":"{{hex:4}}","u":"{{uuid}}"}',
      "CIPHER",
    ).toString();
    expect(out).toContain('"a":"CIPHER"');
    expect(out).toMatch(/"n":"[0-9a-f]{4}"/);
    expect(out).not.toContain("{{");
  });

  it("decodeMultipartBody / decodeXmlBody / decodeAnyBody find the field in raw bodies", () => {
    const aesKey = deriveAesKey("key");
    const ct = encryptField(Buffer.from("whoami"), aesKey);
    const mp = Buffer.from(
      `--x\r\nContent-Disposition: form-data; name="desc"\r\n\r\n${ct}\r\n--x--\r\n`,
    );
    expect(decodeMultipartBody(mp, "desc", aesKey)?.toString()).toBe("whoami");
    expect(decodeAnyBody(mp, "desc", aesKey)?.toString()).toBe("whoami");
    const xml = Buffer.from(`<env><token>${ct}</token></env>`);
    expect(decodeXmlBody(xml, "token", aesKey)?.toString()).toBe("whoami");
    expect(decodeAnyBody(xml, "token", aesKey)?.toString()).toBe("whoami");
    const json = Buffer.from(`{"content":"${ct}"}`);
    expect(decodeAnyBody(json, "content", aesKey)?.toString()).toBe("whoami");
  });
});
