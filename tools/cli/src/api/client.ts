import type {
  ApiErrorResponse,
  CommandConfigVO,
  MainConfig,
  MemShellGenerateRequest,
  MemShellGenerateResponse,
  PackerTree,
  ProbeShellGenerateRequest,
  ProbeShellGenerateResponse,
  ServerConfig,
  VersionInfo,
} from "./types.js";

export type FetchLike = typeof fetch;

/** Error thrown when the API responds with a non-2xx status. */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly url: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface MemPartyClientOptions {
  /** Base URL of the MemShellParty backend, e.g. https://party.mem.mk */
  baseUrl: string;
  /** Injectable fetch implementation (defaults to global fetch). Useful for testing. */
  fetch?: FetchLike;
  /** Per-request timeout in milliseconds. Default 30000. */
  timeoutMs?: number;
}

/**
 * Typed client for the MemShellParty HTTP API.
 * Knows nothing about the CLI or MCP — it is a pure transport layer so every
 * entrypoint (flags, wizard, MCP) can share it.
 */
export class MemPartyClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;

  constructor(options: MemPartyClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    if (typeof this.fetchImpl !== "function") {
      throw new Error(
        "No fetch implementation available. Use Node.js >= 18 or pass a custom fetch.",
      );
    }
  }

  // ---------- config ----------

  getServers(): Promise<ServerConfig> {
    return this.request<ServerConfig>("GET", "/api/config/servers");
  }

  getConfig(): Promise<MainConfig> {
    return this.request<MainConfig>("GET", "/api/config");
  }

  getPackerTree(): Promise<PackerTree> {
    return this.request<PackerTree>("GET", "/api/config/packers/tree");
  }

  getPackers(): Promise<string[]> {
    return this.request<string[]>("GET", "/api/config/packers");
  }

  getCommandConfigs(): Promise<CommandConfigVO> {
    return this.request<CommandConfigVO>("GET", "/api/config/command/configs");
  }

  getVersion(): Promise<VersionInfo> {
    return this.request<VersionInfo>("GET", "/api/version");
  }

  // ---------- generation ----------

  generateMemShell(req: MemShellGenerateRequest): Promise<MemShellGenerateResponse> {
    return this.request<MemShellGenerateResponse>("POST", "/api/memshell/generate", {
      json: req,
    });
  }

  generateProbe(req: ProbeShellGenerateRequest): Promise<ProbeShellGenerateResponse> {
    return this.request<ProbeShellGenerateResponse>("POST", "/api/probe/generate", {
      json: req,
    });
  }

  /** Parse a fully-qualified class name from a base64-encoded .class file. */
  parseClassName(classBase64: string): Promise<string> {
    return this.request<string>("POST", "/api/className", {
      text: classBase64,
      raw: true,
    });
  }

  // ---------- transport ----------

  private async request<T>(
    method: string,
    path: string,
    opts: { json?: unknown; text?: string; raw?: boolean } = {},
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {};
    let body: string | undefined;

    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.json);
    } else if (opts.text !== undefined) {
      headers["Content-Type"] = "text/plain";
      body = opts.text;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        body,
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new ApiError(`Request timed out after ${this.timeoutMs}ms`, 0, url);
      }
      throw new ApiError(
        `Failed to reach ${url}: ${(err as Error).message}`,
        0,
        url,
      );
    } finally {
      clearTimeout(timer);
    }

    const rawText = await response.text();

    if (!response.ok) {
      let message = rawText || response.statusText;
      try {
        const parsed = JSON.parse(rawText) as ApiErrorResponse;
        if (parsed?.error) message = parsed.error;
      } catch {
        // body was not JSON — keep raw text
      }
      throw new ApiError(message, response.status, url);
    }

    if (opts.raw) {
      return rawText as unknown as T;
    }
    if (rawText === "") {
      return undefined as unknown as T;
    }
    return JSON.parse(rawText) as T;
  }
}
