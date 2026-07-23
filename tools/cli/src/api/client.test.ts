import { describe, expect, it, vi } from "vitest";

import { ApiError, MemPartyClient } from "./client.js";

function jsonResponse(body: unknown, init: Partial<{ status: number; ok: boolean }> = {}): Response {
  const status = init.status ?? 200;
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("MemPartyClient", () => {
  it("strips trailing slashes from the base URL and builds GET requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ Tomcat: ["Listener"] }));
    const client = new MemPartyClient({ baseUrl: "http://host:8080/", fetch: fetchMock });

    const servers = await client.getServers();

    expect(servers).toEqual({ Tomcat: ["Listener"] });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("http://host:8080/api/config/servers");
    expect(init.method).toBe("GET");
  });

  it("POSTs JSON bodies with the right content type", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ memShellResult: {}, packResult: "abc" }));
    const client = new MemPartyClient({ baseUrl: "http://host", fetch: fetchMock });

    await client.generateMemShell({
      shellConfig: { server: "Tomcat", shellTool: "Godzilla", shellType: "Listener" },
      shellToolConfig: {},
      injectorConfig: {},
      packer: "Base64",
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("http://host/api/memshell/generate");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body).packer).toBe("Base64");
  });

  it("sends parseClassName as a raw text body and returns raw text", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("com.example.Foo", { status: 200 }));
    const client = new MemPartyClient({ baseUrl: "http://host", fetch: fetchMock });

    const name = await client.parseClassName("QkFTRTY0");

    expect(name).toBe("com.example.Foo");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("http://host/api/className");
    expect(init.headers["Content-Type"]).toBe("text/plain");
    expect(init.body).toBe("QkFTRTY0");
  });

  it("throws ApiError with the server-provided error message", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ error: "bad server" }, { status: 400 }));
    const client = new MemPartyClient({ baseUrl: "http://host", fetch: fetchMock });

    await expect(client.getConfig()).rejects.toMatchObject({
      name: "ApiError",
      status: 400,
      message: "bad server",
    });
  });

  it("wraps network failures in ApiError with status 0", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const client = new MemPartyClient({ baseUrl: "http://host", fetch: fetchMock });

    const err = await client.getServers().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/ECONNREFUSED/);
  });
});
