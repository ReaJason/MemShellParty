import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { aesEcbDecrypt, aesEcbEncrypt, gunzipLenient, gzip, md5Hex, md5Key16 } from "./crypto.js";
import {
  downloadGodzilla,
  execGodzilla,
  testGodzilla,
  uploadGodzilla,
} from "./godzilla.js";

const GATE = "gdz-gate-value";
const PASS = "pass";
const XC = md5Key16("key"); // 3c6e0b8a9c15224a
const WRAP = md5Hex(PASS + XC).toUpperCase();

/** Parse godzilla's `Parameter.serialize` stream (after gunzip). */
function parseSerialized(data: Buffer): Map<string, Buffer> {
  const map = new Map<string, Buffer>();
  let off = 0;
  let key: number[] = [];
  while (off < data.length) {
    const b = data[off]!;
    off++;
    if (b === 0x02) {
      const len = data.readUInt32LE(off);
      off += 4;
      map.set(Buffer.from(key).toString("utf8"), data.subarray(off, off + len));
      off += len;
      key = [];
    } else {
      key.push(b);
    }
  }
  return map;
}

interface MockState {
  payloadLoaded: boolean;
  sawCookieOnSecondRequest: boolean;
  basicsInfoCalls: number;
  /** In-memory remote filesystem for the file-transfer methods. */
  files: Map<string, Buffer>;
  /** Fail the next N download reads (returns garbage) to exercise retry. */
  failNextReads: number;
  /** Fail the next N upload chunks (returns an error string). */
  failNextUploads: number;
  /** When set, mode=fileSize lies and returns this string. */
  fakeSize?: string;
  /** When set, mode=fileSize returns these raw bytes (charset tests). */
  fakeSizeRaw?: Buffer;
  /**
   * When set, the mock emulates a server whose platform default charset is
   * this encoding: getBasicsInfo reports it as file.encoding, and fileName
   * parameter bytes are decoded with it.
   */
  fileEncoding?: string;
}

function newMockState(): MockState {
  return {
    payloadLoaded: false,
    sawCookieOnSecondRequest: false,
    basicsInfoCalls: 0,
    files: new Map(),
    failNextReads: 0,
    failNextUploads: 0,
  };
}

function startMock(state: MockState): Promise<Server> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const fail = (text = "") => res.writeHead(200).end(text);
      const ua = req.headers["user-agent"] ?? "";
      if (!ua.includes(GATE)) return fail();

      const body = Buffer.concat(chunks).toString("utf8");
      let param: string | null = null;
      for (const pair of body.split("&")) {
        const i = pair.indexOf("=");
        if (i > 0 && pair.slice(0, i) === PASS) {
          param = decodeURIComponent(pair.slice(i + 1));
        }
      }
      if (param === null) return fail();

      let data: Buffer;
      try {
        data = aesEcbDecrypt(Buffer.from(param, "base64"), XC);
      } catch {
        // wrong key on a real shell: exception swallowed -> empty body
        return fail();
      }

      // payload class upload: define it, hand out a session cookie
      if (data.readUInt32BE(0) === 0xcafebabe) {
        state.payloadLoaded = true;
        res.setHeader("Set-Cookie", "JSESSIONID=abc123; Path=/");
        return fail();
      }
      if (!state.payloadLoaded) return fail();

      if (req.headers.cookie?.includes("JSESSIONID=abc123")) {
        state.sawCookieOnSecondRequest = true;
      }

      const params = parseSerialized(gunzipLenient(data));
      const method = params.get("methodName")?.toString();
      const reply = (out: string | Buffer) => {
        const wrapped =
          WRAP.slice(0, 16) +
          aesEcbEncrypt(gzip(typeof out === "string" ? Buffer.from(out) : out), XC).toString(
            "base64",
          ) +
          WRAP.slice(16);
        res.writeHead(200).end(wrapped);
      };
      // the payload decodes parameter strings with the platform default charset
      const fileNameOf = (): string => {
        const raw = params.get("fileName");
        if (!raw) return "";
        if (state.fileEncoding) {
          try {
            return new TextDecoder(state.fileEncoding).decode(raw);
          } catch {
            return raw.toString("utf8");
          }
        }
        return raw.toString("utf8");
      };

      if (method === "test") return reply("ok");
      if (method === "getBasicsInfo") {
        state.basicsInfoCalls++;
        const osName = req.url === "/godzilla-linux" ? "Linux" : "Windows 10";
        const enc = state.fileEncoding ? `file.encoding : ${state.fileEncoding}\n` : "";
        return reply(`OsInfo : os.name: ${osName} os.version: 1 os.arch: amd64\n${enc}`);
      }
      if (method === "execCommand") {
        const n = Number(params.get("argsCount")?.toString() ?? "0");
        const argv: string[] = [];
        for (let i = 0; i < n; i++) argv.push(params.get(`arg-${i}`)?.toString() ?? "");
        return reply(`MOCK-EXEC:${argv.join(" ")}`);
      }

      // ---- file-transfer methods (mirrors the payload's semantics) ----
      if (method === "uploadFile") {
        const name = fileNameOf();
        const value = params.get("fileValue");
        if (!name || value === undefined) return reply("No parameter fileName and fileValue");
        state.files.set(name, Buffer.from(value));
        return reply("ok");
      }
      if (method === "bigFileUpload") {
        if (state.failNextUploads > 0) {
          state.failNextUploads--;
          return reply("Exception errMsg:mock injected failure");
        }
        const name = fileNameOf();
        const contents = params.get("fileContents");
        const posText = params.get("position")?.toString();
        if (!name || contents === undefined) return reply("Exception errMsg:no parameter");
        const existing = state.files.get(name) ?? Buffer.alloc(0);
        if (posText === undefined) {
          // no position -> append
          state.files.set(name, Buffer.concat([existing, contents]));
        } else {
          // absolute offset, RandomAccessFile semantics (gap zero-filled)
          const pos = Number.parseInt(posText, 10);
          const out = Buffer.alloc(Math.max(existing.length, pos + contents.length));
          existing.copy(out, 0);
          contents.copy(out, pos);
          state.files.set(name, out);
        }
        return reply("ok");
      }
      if (method === "bigFileDownload") {
        const name = fileNameOf();
        const mode = params.get("mode")?.toString() ?? "";
        const file = state.files.get(name);
        if (mode === "fileSize") {
          if (state.fakeSizeRaw !== undefined) return reply(state.fakeSizeRaw);
          if (state.fakeSize !== undefined) return reply(state.fakeSize);
          return reply(String(file?.length ?? 0)); // File.length(): 0 for missing
        }
        if (mode === "read") {
          if (state.failNextReads > 0) {
            state.failNextReads--;
            return reply("Exception errMsg:mock injected failure");
          }
          if (file === undefined) {
            return reply(`Exception errMsg:java.io.FileNotFoundException: ${name} (No such file or directory)`);
          }
          const pos = Number.parseInt(params.get("position")?.toString() ?? "0", 10);
          const num = Number.parseInt(params.get("readByteNum")?.toString() ?? "0", 10);
          // real payload: read(byte[0]) returns 0 == buffer.length -> empty success
          if (num === 0) return reply(Buffer.alloc(0));
          // real payload: read() at EOF returns -1 -> copyOf(b, -1) -> "Exception errMsg:-1"
          if (pos >= file.length) return reply("Exception errMsg:-1");
          return reply(file.subarray(pos, Math.min(pos + num, file.length)));
        }
        return reply("no mode");
      }
      return fail();
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

describe("testGodzilla", () => {
  let server: Server;
  let base: string;
  const state: MockState = newMockState();

  beforeAll(async () => {
    server = await startMock(state);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("uploads the payload and verifies the test call", async () => {
    state.payloadLoaded = false;
    const result = await testGodzilla(`${base}/godzilla`, "pass", "key", { headerValue: GATE });
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/"test" returned ok/);
  });

  it("relays the session cookie to the second request", () => {
    expect(state.sawCookieOnSecondRequest).toBe(true);
  });

  it("fails with a wrong key", async () => {
    state.payloadLoaded = false;
    const result = await testGodzilla(`${base}/godzilla`, "pass", "wrong", { headerValue: GATE });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("wrong pass/key");
  });

  it("fails with a wrong pass (wrapper mismatch)", async () => {
    state.payloadLoaded = false;
    const result = await testGodzilla(`${base}/godzilla`, "nope", "key", { headerValue: GATE });
    expect(result.ok).toBe(false);
  });

  it("fails without the gate header", async () => {
    state.payloadLoaded = false;
    const result = await testGodzilla(`${base}/godzilla`, "pass", "key");
    expect(result.ok).toBe(false);
  });

  it("reports network errors", async () => {
    const result = await testGodzilla("http://127.0.0.1:1/x", "pass", "key", { timeoutMs: 2000 });
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

describe("execGodzilla", () => {
  let server: Server;
  let base: string;
  const state: MockState = newMockState();

  beforeAll(async () => {
    server = await startMock(state);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("wraps the command in cmd.exe on auto-detected Windows", async () => {
    const result = await execGodzilla(`${base}/godzilla`, "pass", "key", "whoami", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.output).toBe("MOCK-EXEC:cmd.exe /c whoami");
  });

  it("wraps the command in /bin/sh on auto-detected Linux", async () => {
    const result = await execGodzilla(`${base}/godzilla-linux`, "pass", "key", "id", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.output).toBe("MOCK-EXEC:/bin/sh -c id");
  });

  it("skips OS detection when os is given explicitly", async () => {
    state.basicsInfoCalls = 0;
    const result = await execGodzilla(`${base}/godzilla`, "pass", "key", "id", {
      headerValue: GATE,
      os: "linux",
    });
    expect(result.ok).toBe(true);
    expect(result.output).toBe("MOCK-EXEC:/bin/sh -c id");
    expect(state.basicsInfoCalls).toBe(0);
  });

  it("fails with a wrong key", async () => {
    const result = await execGodzilla(`${base}/godzilla`, "pass", "wrong", "id", {
      headerValue: GATE,
      os: "linux",
    });
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("fails without the gate header", async () => {
    const result = await execGodzilla(`${base}/godzilla`, "pass", "key", "id", { os: "linux" });
    expect(result.ok).toBe(false);
  });
});


describe("downloadGodzilla", () => {
  let server: Server;
  let base: string;
  const state: MockState = newMockState();

  beforeAll(async () => {
    server = await startMock(state);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  const BINARY = (() => {
    // includes the gzip magic prefix and non-UTF8 bytes — the transfer must
    // not mangle them through the gzip envelope
    const b = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) b[i] = i;
    b[0] = 0x1f;
    b[1] = 0x8b;
    return b;
  })();

  it("downloads a small binary file byte-for-byte", async () => {
    state.files.set("/tmp/a.bin", BINARY);
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/a.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.bytes).toBe(BINARY.length);
    expect(result.data?.equals(BINARY)).toBe(true);
  });

  it("downloads a file in small chunks (offset math)", async () => {
    const big = Buffer.alloc(1000);
    for (let i = 0; i < big.length; i++) big[i] = (i * 31 + 7) % 256;
    state.files.set("/tmp/chunked.bin", big);
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/chunked.bin", {
      headerValue: GATE,
      chunkSize: 7,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(big)).toBe(true);
  });

  it("downloads an empty file", async () => {
    state.files.set("/tmp/empty.bin", Buffer.alloc(0));
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/empty.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.bytes).toBe(0);
    expect(result.data?.length).toBe(0);
  });

  it("fails for a missing remote file (size 0 probe unmasks it)", async () => {
    state.files.delete("/tmp/nope.bin");
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/nope.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/FileNotFoundException|read failed/);
  });

  it("fails when the size probe is garbage", async () => {
    state.fakeSize = "Exception errMsg:boom";
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/a.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("cannot get remote file size");
    state.fakeSize = undefined;
  });

  it("refuses files over 2 GiB", async () => {
    state.fakeSize = "3000000000";
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/huge.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("2 GiB");
    state.fakeSize = undefined;
  });

  it("decodes GBK error text from non-UTF-8 servers", async () => {
    // "系统找不到指定的路径。" in GBK — what a Chinese-Windows payload returns
    state.fakeSizeRaw = Buffer.from([
      0xcf, 0xb5, 0xcd, 0xb3, 0xd5, 0xd2, 0xb2, 0xbb, 0xb5, 0xbd, 0xd6, 0xb8, 0xb6, 0xa8, 0xb5,
      0xc4, 0xc2, 0xb7, 0xbe, 0xb6, 0xa1, 0xa3,
    ]);
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/missing.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("系统找不到指定的路径");
    state.fakeSizeRaw = undefined;
  });

  it("retries failed reads and succeeds", async () => {
    state.files.set("/tmp/flaky.bin", BINARY);
    state.failNextReads = 2; // CHUNK_ATTEMPTS is 3
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/flaky.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(BINARY)).toBe(true);
  });

  it("gives up after the retry budget", async () => {
    state.files.set("/tmp/dead.bin", BINARY);
    state.failNextReads = 10;
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/dead.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/read failed at offset 0/);
    state.failNextReads = 0;
  });

  it("fails with a wrong key", async () => {
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "wrong", "/tmp/a.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
  });

  it("fails without the gate header", async () => {
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/a.bin");
    expect(result.ok).toBe(false);
  });

  it("encodes non-ASCII paths in --remote-charset (GBK server)", async () => {
    state.fileEncoding = "GBK";
    const name = "C:\\测试\\配置.ini";
    state.files.set(name, BINARY);
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", name, {
      headerValue: GATE,
      remoteCharset: "GBK",
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(BINARY)).toBe(true);
    state.fileEncoding = undefined;
  });

  it("UTF-8 default does not reach non-ASCII paths on a GBK server", async () => {
    state.fileEncoding = "GBK";
    const name = "C:\\测试\\配置.ini";
    state.files.set(name, BINARY);
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", name, {
      headerValue: GATE,
    });
    // the mojibake name simply does not exist remotely — a clean, readable failure
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/FileNotFoundException|read failed|cannot get/);
    state.fileEncoding = undefined;
  });

  it("still works for non-ASCII paths on a UTF-8 server with the default", async () => {
    const name = "/opt/应用/config.ini";
    state.files.set(name, BINARY);
    const result = await downloadGodzilla(`${base}/godzilla`, "pass", "key", name, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(BINARY)).toBe(true);
  });
});

describe("uploadGodzilla", () => {
  let server: Server;
  let base: string;
  const state: MockState = newMockState();

  beforeAll(async () => {
    server = await startMock(state);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("uploads a small file in a single call and verifies the size", async () => {
    const data = Buffer.from("hello godzilla upload \u0000\u00ff", "latin1");
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/up.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.bytes).toBe(data.length);
    expect(state.files.get("/tmp/up.bin")?.equals(data)).toBe(true);
  });

  it("truncates an existing longer remote file", async () => {
    state.files.set("/tmp/trunc.bin", Buffer.alloc(100, 0x41));
    const data = Buffer.from("short");
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/trunc.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(state.files.get("/tmp/trunc.bin")?.equals(data)).toBe(true);
  });

  it("uploads in small chunks with absolute offsets", async () => {
    const data = Buffer.alloc(1000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 13 + 5) % 256;
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/bigup.bin", data, {
      headerValue: GATE,
      chunkSize: 7,
    });
    expect(result.ok).toBe(true);
    expect(state.files.get("/tmp/bigup.bin")?.equals(data)).toBe(true);
  });

  it("uploads an empty file (create/truncate)", async () => {
    state.files.set("/tmp/emptyup.bin", Buffer.from("old content"));
    const result = await uploadGodzilla(
      `${base}/godzilla`,
      "pass",
      "key",
      "/tmp/emptyup.bin",
      Buffer.alloc(0),
      { headerValue: GATE },
    );
    expect(result.ok).toBe(true);
    expect(state.files.get("/tmp/emptyup.bin")?.length).toBe(0);
  });

  it("retries failed chunks", async () => {
    const data = Buffer.alloc(50, 0x62);
    state.failNextUploads = 2;
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/flaky.bin", data, {
      headerValue: GATE,
      chunkSize: 10,
    });
    expect(result.ok).toBe(true);
    expect(state.files.get("/tmp/flaky.bin")?.equals(data)).toBe(true);
  });

  it("aborts after the retry budget and reports the offset", async () => {
    const data = Buffer.alloc(50, 0x63);
    state.failNextUploads = 10;
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/dead.bin", data, {
      headerValue: GATE,
      chunkSize: 10,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/upload failed at offset 0\/50/);
    state.failNextUploads = 0;
  });

  it("fails when the size verification mismatches", async () => {
    const data = Buffer.from("verify me");
    state.fakeSize = "12345";
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/ver.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/remote size mismatch/);
    state.fakeSize = undefined;
  });

  it("round-trips: chunked upload then download", async () => {
    const data = Buffer.alloc(500);
    for (let i = 0; i < data.length; i++) data[i] = (i * 17 + 3) % 256;
    const up = await uploadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/rt.bin", data, {
      headerValue: GATE,
      chunkSize: 64,
    });
    expect(up.ok).toBe(true);
    const down = await downloadGodzilla(`${base}/godzilla`, "pass", "key", "/tmp/rt.bin", {
      headerValue: GATE,
      chunkSize: 128,
    });
    expect(down.ok).toBe(true);
    expect(down.data?.equals(data)).toBe(true);
  });

  it("uploads to a non-ASCII path on a GBK server (--remote-charset)", async () => {
    state.fileEncoding = "GBK";
    const name = "D:\\数据\\上传-日志.bin";
    const data = Buffer.from("gbk upload content", "utf8");
    const result = await uploadGodzilla(`${base}/godzilla`, "pass", "key", name, data, {
      headerValue: GATE,
      remoteCharset: "GBK",
    });
    expect(result.ok).toBe(true);
    expect(state.files.get(name)?.equals(data)).toBe(true);
    state.fileEncoding = undefined;
  });
});
