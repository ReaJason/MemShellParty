import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  downloadBehinder,
  execBehinder,
  testBehinder,
  uploadBehinder,
} from "./behinder.js";
import { readStringConstant } from "./classfile.js";
import { aesEcbDecrypt, aesEcbEncrypt, md5Hex, md5Key16 } from "./crypto.js";

const GATE = "bh-gate-value";
const KEY = md5Key16("rebeyond"); // e45e329feb5d925b

/** In-memory remote FS + failure injection for the FileOperation payload. */
interface BhMockState {
  files: Map<string, Buffer>;
  failNextAppends: number;
  failNextReads: number;
  corruptCheck: boolean;
  /** Number of mode=check calls seen (must stay 0 for big-file transfers). */
  checkCalls: number;
  /** When set, checkExist lies about the remote size. */
  fakeSize?: number;
}

function newBhMockState(): BhMockState {
  return {
    files: new Map(),
    failNextAppends: 0,
    failNextReads: 0,
    corruptCheck: false,
    checkCalls: 0,
  };
}

function echoReply(classBytes: Buffer, rawWithMagic: boolean): Buffer {
  const content = readStringConstant(classBytes, "content") ?? "";
  const json = JSON.stringify({
    status: Buffer.from("success").toString("base64"),
    msg: Buffer.from(content).toString("base64"),
  });
  const encrypted = aesEcbEncrypt(Buffer.from(json, "utf8"), KEY);
  if (rawWithMagic) {
    const magic = parseInt(KEY.slice(0, 2), 16) % 16;
    return Buffer.concat([encrypted, Buffer.alloc(magic, 0x55)]);
  }
  return Buffer.from(encrypted.toString("base64"));
}

/** Emulate the Cmd payload: run status/msg envelope for the injected `cmd`. */
function cmdReply(classBytes: Buffer): Buffer {
  const cmd = readStringConstant(classBytes, "cmd") ?? "";
  const status = cmd === "please-fail" ? "fail" : "success";
  const msg = cmd === "please-fail" ? "boom" : `MOCK-EXEC:${cmd}`;
  const json = JSON.stringify({
    status: Buffer.from(status).toString("base64"),
    msg: Buffer.from(msg).toString("base64"),
  });
  return Buffer.from(aesEcbEncrypt(Buffer.from(json, "utf8"), KEY).toString("base64"));
}

/**
 * Emulate the FileOperation payload for the modes the CLI uses.
 * Envelope encoding mirrors buildJson(map, true): every value base64'd once,
 * JSON, AES, base64 — so downloadPart's msg (already base64 in the payload)
 * goes out double-encoded, exactly like the real shell.
 */
function fileOpReply(state: BhMockState, classBytes: Buffer): Buffer | null {
  const mode = readStringConstant(classBytes, "mode");
  if (mode === null) return null;
  const path = readStringConstant(classBytes, "path") ?? "";
  const content = readStringConstant(classBytes, "content");
  const blockIndex = Number(readStringConstant(classBytes, "blockIndex") ?? "0");
  const blockSize = Number(readStringConstant(classBytes, "blockSize") ?? "0");

  const envelope = (status: string, msg: string): Buffer => {
    const json = JSON.stringify({
      status: Buffer.from(status).toString("base64"),
      msg: Buffer.from(msg, "utf8").toString("base64"),
    });
    return Buffer.from(aesEcbEncrypt(Buffer.from(json, "utf8"), KEY).toString("base64"));
  };

  switch (mode) {
    case "checkExist": {
      if (state.fakeSize !== undefined) return envelope("success", String(state.fakeSize));
      const file = state.files.get(path);
      if (file === undefined) return envelope("fail", ""); // payload: throw new Exception("")
      return envelope("success", String(file.length));
    }
    case "create": {
      const data = Buffer.from(content ?? "", "base64");
      state.files.set(path, data); // FileOutputStream(path) — truncate + write
      return envelope("success", `${path}上传完成，远程文件大小:${data.length}`);
    }
    case "append": {
      if (state.failNextAppends > 0) {
        state.failNextAppends--;
        return envelope("fail", "mock injected failure");
      }
      const data = Buffer.from(content ?? "", "base64");
      state.files.set(path, Buffer.concat([state.files.get(path) ?? Buffer.alloc(0), data]));
      return envelope("success", `${path}追加完成，远程文件大小:${state.files.get(path)!.length}`);
    }
    case "downloadPart": {
      const file = state.files.get(path);
      if (file === undefined) return envelope("fail", `FileNotFoundException: ${path}`);
      const pos = blockIndex * blockSize;
      if (pos >= file.length) return envelope("fail", ""); // EOF -> NegativeArraySizeException
      if (state.failNextReads > 0) {
        state.failNextReads--;
        return envelope("fail", "mock injected failure");
      }
      const chunk = file.subarray(pos, Math.min(pos + blockSize, file.length));
      return envelope("success", chunk.toString("base64"));
    }
    case "check": {
      state.checkCalls++;
      const file = state.files.get(path);
      // empty/missing file -> the payload NPEs on a null msg -> empty body
      if (file === undefined || file.length === 0) return Buffer.alloc(0);
      const md5 = state.corruptCheck ? "0000000000000000" : md5Hex(file).slice(0, 16);
      state.corruptCheck = false;
      return envelope("success", md5);
    }
    default:
      return envelope("fail", `unsupported mode ${mode}`);
  }
}

function startMock(state: BhMockState = newBhMockState()): Promise<Server> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const fail = () => res.writeHead(200).end();
      const ua = req.headers["user-agent"] ?? "";
      if (!ua.includes(GATE)) return fail();

      // Behinder shell: base64(AES(class)) or raw AES(class)
      let classBytes: Buffer | null = null;
      try {
        classBytes = aesEcbDecrypt(Buffer.from(body.toString("latin1").trim(), "base64"), KEY);
      } catch {
        try {
          classBytes = aesEcbDecrypt(body, KEY);
        } catch {
          classBytes = null;
        }
      }
      if (!classBytes || classBytes.readUInt32BE(0) !== 0xcafebabe) return fail();

      const raw = req.url === "/behinder-raw";
      // the FileOperation payload carries a `mode` field
      const fo = fileOpReply(state, classBytes);
      if (fo !== null) {
        res.writeHead(200).end(fo);
        return;
      }
      // the Cmd payload carries a `cmd` field instead of Echo's `content`
      if (readStringConstant(classBytes, "cmd") !== null) {
        res.writeHead(200).end(cmdReply(classBytes));
        return;
      }
      res.writeHead(200).end(echoReply(classBytes, raw));
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

describe("testBehinder", () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = await startMock();
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("verifies the echo round-trip with the right password", async () => {
    const result = await testBehinder(`${base}/behinder`, "rebeyond", { headerValue: GATE });
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/echo verified \(\d+ random bytes/);
  });

  it("handles raw AES responses with a magic suffix", async () => {
    const result = await testBehinder(`${base}/behinder-raw`, "rebeyond", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
  });

  it("fails with a wrong password", async () => {
    const result = await testBehinder(`${base}/behinder`, "wrongpass", { headerValue: GATE });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("wrong password");
  });

  it("fails without the gate header", async () => {
    const result = await testBehinder(`${base}/behinder`, "rebeyond");
    expect(result.ok).toBe(false);
  });

  it("reports network errors", async () => {
    const result = await testBehinder("http://127.0.0.1:1/x", "rebeyond", { timeoutMs: 2000 });
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });
});

describe("execBehinder", () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = await startMock();
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("runs the injected command and returns its output", async () => {
    const result = await execBehinder(`${base}/behinder`, "rebeyond", "id", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.output).toBe("MOCK-EXEC:id");
  });

  it("handles commands with spaces and shell metacharacters", async () => {
    const cmd = "sh -c 'echo a; echo b' | tail -1";
    const result = await execBehinder(`${base}/behinder`, "rebeyond", cmd, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.output).toBe(`MOCK-EXEC:${cmd}`);
  });

  it("surfaces a remote failure status with its message", async () => {
    const result = await execBehinder(`${base}/behinder`, "rebeyond", "please-fail", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("boom");
  });

  it("fails with a wrong password", async () => {
    const result = await execBehinder(`${base}/behinder`, "wrongpass", "id", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
  });
});


describe("downloadBehinder", () => {
  let server: Server;
  let base: string;
  const state: BhMockState = newBhMockState();

  beforeAll(async () => {
    server = await startMock(state);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  const BINARY = (() => {
    const b = Buffer.alloc(256);
    for (let i = 0; i < 256; i++) b[i] = i;
    b[0] = 0x1f;
    b[1] = 0x8b; // gzip magic — must survive the envelope
    return b;
  })();

  it("downloads a small binary file byte-for-byte (double base64 unwrap)", async () => {
    state.files.set("/tmp/a.bin", BINARY);
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/a.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.bytes).toBe(BINARY.length);
    expect(result.data?.equals(BINARY)).toBe(true);
  });

  it("downloads in small chunks (absolute block offsets)", async () => {
    const big = Buffer.alloc(1000);
    for (let i = 0; i < big.length; i++) big[i] = (i * 29 + 11) % 256;
    state.files.set("/tmp/chunked.bin", big);
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/chunked.bin", {
      headerValue: GATE,
      downloadChunkSize: 7,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(big)).toBe(true);
  });

  it("downloads an empty file and skips the hash check", async () => {
    state.files.set("/tmp/empty.bin", Buffer.alloc(0));
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/empty.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.bytes).toBe(0);
    expect(result.detail).toMatch(/hash check skipped/);
  });

  it("fails for a missing remote file", async () => {
    state.files.delete("/tmp/nope.bin");
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/nope.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/not found/);
  });

  it("retries failed chunks and succeeds", async () => {
    state.files.set("/tmp/flaky.bin", BINARY);
    state.failNextReads = 2; // budget is 3 attempts per chunk
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/flaky.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(BINARY)).toBe(true);
  });

  it("gives up after the retry budget", async () => {
    state.files.set("/tmp/dead.bin", BINARY);
    state.failNextReads = 99;
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/dead.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/chunk 0 .* failed/);
    state.failNextReads = 0;
  });

  it("detects a hash mismatch (file changed mid-transfer)", async () => {
    state.files.set("/tmp/mut.bin", Buffer.from("original content"));
    state.corruptCheck = true;
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/mut.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/hash mismatch/);
  });

  it("handles a non-ASCII remote path", async () => {
    const name = "/tmp/测试文件-日志.bin";
    state.files.set(name, BINARY);
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", name, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(BINARY)).toBe(true);
  });

  it("skips the expensive MD5 check over the limit and verifies the size", async () => {
    const big = Buffer.alloc(1000, 0x5a);
    state.files.set("/tmp/large.bin", big);
    state.checkCalls = 0;
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/large.bin", {
      headerValue: GATE,
      downloadChunkSize: 100,
      hashCheckLimit: 10,
    });
    expect(result.ok).toBe(true);
    expect(result.data?.equals(big)).toBe(true);
    expect(result.detail).toMatch(/MD5 check skipped, size verified/);
    expect(state.checkCalls).toBe(0);
  });

  it("fails when the post-transfer size check mismatches", async () => {
    state.files.set("/tmp/shift.bin", Buffer.alloc(64, 0x61));
    state.checkCalls = 0;
    state.fakeSize = 999; // the upload flow only calls checkExist when verifying
    const result = await uploadBehinder(
      `${base}/behinder`,
      "rebeyond",
      "/tmp/shift.bin",
      Buffer.alloc(64, 0x61),
      { headerValue: GATE, hashCheckLimit: 10 },
    );
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/size verification failed/);
    expect(state.checkCalls).toBe(0);
    state.fakeSize = undefined;
  });

  it("fails with a wrong password", async () => {
    const result = await downloadBehinder(`${base}/behinder`, "wrongpass", "/tmp/a.bin", {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
  });

  it("fails without the gate header", async () => {
    const result = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/a.bin");
    expect(result.ok).toBe(false);
  });
});

describe("uploadBehinder", () => {
  let server: Server;
  let base: string;
  const state: BhMockState = newBhMockState();

  beforeAll(async () => {
    server = await startMock(state);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("uploads a small file in one create chunk and verifies the MD5", async () => {
    const data = Buffer.from("behinder upload \u0000\u00ff binary", "latin1");
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/up.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(result.bytes).toBe(data.length);
    expect(state.files.get("/tmp/up.bin")?.equals(data)).toBe(true);
  });

  it("uploads a multi-chunk file (create then append)", async () => {
    // 100_000 bytes > 46 080 upload chunk -> 3 chunks
    const data = Buffer.alloc(100_000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 1) % 256;
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/big.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(state.files.get("/tmp/big.bin")?.equals(data)).toBe(true);
  });

  it("truncates an existing longer remote file (first chunk is create)", async () => {
    state.files.set("/tmp/trunc.bin", Buffer.alloc(5000, 0x41));
    const data = Buffer.from("short new content");
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/trunc.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(true);
    expect(state.files.get("/tmp/trunc.bin")?.equals(data)).toBe(true);
  });

  it("uploads an empty file", async () => {
    state.files.set("/tmp/emptyup.bin", Buffer.from("old"));
    const result = await uploadBehinder(
      `${base}/behinder`,
      "rebeyond",
      "/tmp/emptyup.bin",
      Buffer.alloc(0),
      { headerValue: GATE },
    );
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/hash check skipped/);
    expect(state.files.get("/tmp/emptyup.bin")?.length).toBe(0);
  });

  it("aborts on a failed append and warns about a partial file", async () => {
    const data = Buffer.alloc(100_000, 0x61);
    state.failNextAppends = 5; // every append fails
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/part.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/may be incomplete/);
    state.failNextAppends = 0;
  });

  it("detects a hash mismatch after upload", async () => {
    const data = Buffer.from("hash me");
    state.corruptCheck = true;
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/hm.bin", data, {
      headerValue: GATE,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/hash mismatch/);
  });

  it("round-trips: upload then download", async () => {
    const data = Buffer.alloc(60_000);
    for (let i = 0; i < data.length; i++) data[i] = (i * 3 + 19) % 256;
    const up = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/rt.bin", data, {
      headerValue: GATE,
    });
    expect(up.ok).toBe(true);
    const down = await downloadBehinder(`${base}/behinder`, "rebeyond", "/tmp/rt.bin", {
      headerValue: GATE,
      downloadChunkSize: 12345,
    });
    expect(down.ok).toBe(true);
    expect(down.data?.equals(data)).toBe(true);
  });

  it("skips the expensive MD5 check over the limit (upload)", async () => {
    const data = Buffer.alloc(500, 0x62);
    state.checkCalls = 0;
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/bigup.bin", data, {
      headerValue: GATE,
      hashCheckLimit: 10,
    });
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/MD5 check skipped, size verified/);
    expect(state.files.get("/tmp/bigup.bin")?.equals(data)).toBe(true);
    expect(state.checkCalls).toBe(0);
  });

  it("uses the MD5 check under the limit", async () => {
    const data = Buffer.from("small file gets md5 checked");
    state.checkCalls = 0;
    const result = await uploadBehinder(`${base}/behinder`, "rebeyond", "/tmp/smallup.bin", data, {
      headerValue: GATE,
      hashCheckLimit: 1024 * 1024,
    });
    expect(result.ok).toBe(true);
    expect(result.detail).toBeUndefined();
    expect(state.checkCalls).toBe(1);
  });

  it("fails with a wrong password", async () => {
    const result = await uploadBehinder(
      `${base}/behinder`,
      "wrongpass",
      "/tmp/x.bin",
      Buffer.from("x"),
      { headerValue: GATE },
    );
    expect(result.ok).toBe(false);
  });
});
