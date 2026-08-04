/**
 * suo5 connection test.
 *
 * Two wire protocols exist in the wild:
 *
 * - "v2": the zema1/suo5 protocol (also what MemShellParty's `Suo5v2` shells
 *   and the real suo5.jsp speak). Connection test = the client's
 *   `checkConnectMode` in classic mode: POST one base64 frame
 *   `{ac:0x01, id, dt:identifier, a:0x00, m:0x00(checking)}`; the shell echoes
 *   `dt` in frame 1 and returns a session id in frame 2.
 *
 * - "v1": MemShellParty's legacy `Suo5` shell (raw binary single-byte-XOR
 *   frames). Its full-duplex probe (`Content-Type: application/plain`) echoes
 *   back 32 bytes verbatim — that round-trip is the liveness check.
 */
import { randomBytes } from "node:crypto";
import { base64UrlDecode, base64UrlEncode, randomString } from "./crypto.js";
import { postRaw } from "./http.js";
import { buildHeaders, type CommonConnectOptions, type ConnectTestResult } from "./types.js";

export type Suo5Mode = "auto" | "v2" | "v1";

export interface Suo5ConnectOptions extends CommonConnectOptions {
  mode?: Suo5Mode;
}

// ---------- frame codec (zema1/suo5 netrans.DataFrame, base64 variant) ----------

/** suo5's `Marshal`: [klen u8][key][vlen u32 BE][value] per entry. */
export function marshalSuo5Map(entries: Array<[string, Buffer]>): Buffer {
  const parts: Buffer[] = [];
  for (const [key, value] of entries) {
    const keyBytes = Buffer.from(key, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(value.length, 0);
    parts.push(Buffer.from([keyBytes.length]), keyBytes, len, value);
  }
  return Buffer.concat(parts);
}

export function unmarshalSuo5Map(data: Buffer): Map<string, Buffer> {
  const map = new Map<string, Buffer>();
  let off = 0;
  while (off < data.length - 1) {
    const kLen = data[off]!;
    off += 1;
    if (off + kLen > data.length) throw new Error("unexpected eof when read key");
    const key = data.toString("utf8", off, off + kLen);
    off += kLen;
    if (off + 4 > data.length) throw new Error("unexpected eof when read value size");
    const vLen = data.readUInt32BE(off);
    off += 4;
    if (off + vLen > data.length) throw new Error("unexpected eof when read value");
    map.set(key, data.subarray(off, off + vLen));
    off += vLen;
  }
  return map;
}

/** suo5's `DataFrame.MarshalBinaryBase64`. */
export function marshalFrameBase64(data: Buffer): Buffer {
  const obs = randomBytes(2);
  const xored = Buffer.from(data);
  for (let i = 0; i < xored.length; i++) xored[i] = xored[i]! ^ obs[i % 2]!;
  const dataB64 = base64UrlEncode(xored);

  const header = Buffer.alloc(6);
  obs.copy(header, 0);
  header.writeUInt32BE(Buffer.byteLength(dataB64), 2);
  for (let i = 2; i < 6; i++) header[i] = header[i]! ^ obs[i % 2]!;

  return Buffer.concat([Buffer.from(base64UrlEncode(header)), Buffer.from(dataB64)]);
}

export interface Suo5Frame {
  data: Buffer;
  /** offset just past this frame */
  next: number;
}

/** suo5's `ReadFrameBase64` over a flat buffer. Throws on truncation. */
export function unmarshalFrameBase64(buf: Buffer, offset = 0): Suo5Frame {
  if (buf.length - offset < 8) throw new Error("failed to read header base64: truncated");
  const header = base64UrlDecode(buf.toString("latin1", offset, offset + 8));
  if (header.length !== 6) throw new Error("invalid header length");
  const obs = header.subarray(0, 2);
  for (let i = 2; i < 6; i++) header[i] = header[i]! ^ obs[(i - 2) % 2]!;
  const dataLength = header.readUInt32BE(2);
  if (dataLength > 32 * 1024 * 1024) throw new Error(`frame is too big, ${dataLength}`);
  const dataStart = offset + 8;
  if (buf.length - dataStart < dataLength) throw new Error("failed to read data base64: truncated");
  const data = base64UrlDecode(buf.toString("latin1", dataStart, dataStart + dataLength));
  for (let i = 0; i < data.length; i++) data[i] = data[i]! ^ obs[i % 2]!;
  return { data, next: dataStart + dataLength };
}

// ---------- v2 handshake ----------

async function testSuo5V2(
  url: string,
  options: CommonConnectOptions,
): Promise<{ ok: boolean; detail?: string; error?: string }> {
  const identifier = randomString(48);
  const frame = marshalFrameBase64(
    marshalSuo5Map([
      ["ac", Buffer.from([0x01])], // ActionData
      ["id", randomBytes(8)],
      ["dt", Buffer.from(identifier, "utf8")],
      ["a", Buffer.from([0x00])], // classic (non-streaming) check
      ["m", Buffer.from([0x00])], // ConnectionType.Checking
      ["_", randomBytes(Math.floor(Math.random() * 64))], // junk
    ]),
  );

  let response;
  try {
    response = await postRaw(url, frame, {
      headers: buildHeaders({ "Content-Type": "application/octet-stream" }, options),
      timeoutMs: options.timeoutMs,
      insecure: options.insecure,
    });
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }

  try {
    const echoFrame = unmarshalFrameBase64(response.body, 0);
    const echoMap = unmarshalSuo5Map(echoFrame.data);
    const echoed = echoMap.get("dt")?.toString("utf8");
    if (echoed !== identifier) {
      return {
        ok: false,
        error: `HTTP ${response.status}, first frame did not echo the identifier (got ${
          echoed === undefined ? "no dt field" : JSON.stringify(echoed.slice(0, 64))
        })`,
      };
    }
    const sessionFrame = unmarshalFrameBase64(response.body, echoFrame.next);
    const sessionMap = unmarshalSuo5Map(sessionFrame.data);
    const sid = sessionMap.get("dt")?.toString("utf8");
    if (!sid) {
      return { ok: false, error: "second frame carries no session id" };
    }
    return { ok: true, detail: `suo5 v2 handshake ok (session ${sid}, HTTP ${response.status})` };
  } catch (err) {
    return {
      ok: false,
      error: `HTTP ${response.status}, response is not valid suo5 frames (${
        err instanceof Error ? err.message : String(err)
      })`,
    };
  }
}

// ---------- v1 plain echo ----------

async function testSuo5V1(
  url: string,
  options: CommonConnectOptions,
): Promise<{ ok: boolean; detail?: string; error?: string }> {
  const probe = randomBytes(32);
  let response;
  try {
    response = await postRaw(url, probe, {
      headers: buildHeaders({ "Content-Type": "application/plain" }, options),
      timeoutMs: options.timeoutMs,
      insecure: options.insecure,
    });
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
  if (response.body.equals(probe)) {
    return {
      ok: true,
      detail: `suo5 v1 full-duplex echo ok (32 bytes round-trip, HTTP ${response.status})`,
    };
  }
  return {
    ok: false,
    error: `HTTP ${response.status}, expected the 32 probe bytes echoed back, got ${response.body.length} different bytes`,
  };
}

export async function testSuo5(
  url: string,
  options: Suo5ConnectOptions = {},
): Promise<ConnectTestResult> {
  const started = Date.now();
  const mode = options.mode ?? "auto";
  const failures: string[] = [];

  if (mode === "v2" || mode === "auto") {
    const v2 = await testSuo5V2(url, options);
    if (v2.ok) {
      return { ok: true, tool: "suo5", url, detail: v2.detail, durationMs: Date.now() - started };
    }
    failures.push(`v2: ${v2.error}`);
    if (mode === "v2") {
      return {
        ok: false,
        tool: "suo5",
        url,
        error: `${v2.error} — not a suo5(v2) shell?`,
        durationMs: Date.now() - started,
      };
    }
  }
  if (mode === "v1" || mode === "auto") {
    const v1 = await testSuo5V1(url, options);
    if (v1.ok) {
      return { ok: true, tool: "suo5", url, detail: v1.detail, durationMs: Date.now() - started };
    }
    failures.push(`v1: ${v1.error}`);
  }

  return {
    ok: false,
    tool: "suo5",
    url,
    error: failures.join("; ") + " — not a suo5 shell (or missing gate header)",
    durationMs: Date.now() - started,
  };
}
