/**
 * Minimal raw-HTTP POST helper for the shell connection testers.
 *
 * Uses node:http/https directly instead of fetch because the testers need
 * exact control over the body bytes, access to raw Set-Cookie headers, an
 * optional insecure-TLS mode, and no automatic redirect following.
 */
import http from "node:http";
import https from "node:https";

export interface RawPostOptions {
  headers?: Record<string, string>;
  timeoutMs?: number;
  /** Skip TLS certificate verification (self-signed targets). */
  insecure?: boolean;
}

export interface RawPostResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  durationMs: number;
}

export class HttpRequestError extends Error {
  constructor(
    message: string,
    readonly url: string,
    override readonly cause?: unknown,
  ) {
    super(message);
    this.name = "HttpRequestError";
  }
}

/** POST `body` to `url`, return the raw response. Never follows redirects. */
export function postRaw(
  url: string,
  body: Buffer,
  options: RawPostOptions = {},
): Promise<RawPostResult> {
  const { headers = {}, timeoutMs = 30_000, insecure = false } = options;
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return Promise.reject(new HttpRequestError(`invalid URL: ${url}`, url));
  }
  const isHttps = target.protocol === "https:";
  if (!isHttps && target.protocol !== "http:") {
    return Promise.reject(new HttpRequestError(`unsupported protocol: ${target.protocol}`, url));
  }

  // Opt-in proxying for traffic inspection (Burp & co.): set MEMPARTY_PROXY
  // e.g. http://127.0.0.1:8083. Deliberately NOT HTTP_PROXY — shell traffic
  // must never leak into a system-wide proxy by accident. http:// targets
  // only (absolute-URI request line); https:// still goes direct.
  let proxy: URL | null = null;
  if (!isHttps && process.env.MEMPARTY_PROXY) {
    try {
      proxy = new URL(process.env.MEMPARTY_PROXY);
    } catch {
      return Promise.reject(
        new HttpRequestError(`invalid MEMPARTY_PROXY: ${process.env.MEMPARTY_PROXY}`, url),
      );
    }
  }

  return new Promise<RawPostResult>((resolve, reject) => {
    const started = Date.now();
    const transport = isHttps ? https : http;
    const req = transport.request(
      {
        method: "POST",
        hostname: proxy ? proxy.hostname : target.hostname,
        port: proxy ? proxy.port || 8080 : target.port || (isHttps ? 443 : 80),
        path: proxy ? target.toString() : `${target.pathname}${target.search}`,
        // agent:false — never reuse a pooled socket. A shell server may close
        // the connection right after an empty response, and reusing such a
        // socket surfaces as a spurious ECONNRESET on the next probe.
        agent: false,
        headers: {
          "Content-Length": String(body.length),
          ...headers,
        },
        timeout: timeoutMs,
        ...(isHttps && insecure ? { rejectUnauthorized: false } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
            durationMs: Date.now() - started,
          }),
        );
        res.on("error", (err) => reject(new HttpRequestError(err.message, url, err)));
      },
    );
    req.on("timeout", () => req.destroy(new Error(`request timed out after ${timeoutMs} ms`)));
    req.on("error", (err) => reject(new HttpRequestError(err.message, url, err)));
    req.write(body);
    req.end();
  });
}

/** Extract cookie pairs (`name=value`) from a response's Set-Cookie headers. */
export function extractCookies(headers: http.IncomingHttpHeaders): string[] {
  const setCookie = headers["set-cookie"];
  if (!setCookie) return [];
  return setCookie.map((line) => line.split(";", 1)[0]!.trim()).filter(Boolean);
}
