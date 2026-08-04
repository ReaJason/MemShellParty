import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { randomString } from "./crypto.js";
import {
  marshalFrameBase64,
  marshalSuo5Map,
  testSuo5,
  unmarshalFrameBase64,
  unmarshalSuo5Map,
} from "./suo5.js";

describe("suo5 map codec", () => {
  it("round-trips multiple entries incl. binary values", () => {
    const entries: Array<[string, Buffer]> = [
      ["ac", Buffer.from([0x01])],
      ["id", Buffer.from("tun-1234", "utf8")],
      ["dt", Buffer.alloc(257, 0xab)],
      ["_", Buffer.alloc(0)],
    ];
    const decoded = unmarshalSuo5Map(marshalSuo5Map(entries));
    expect(decoded.get("ac")).toEqual(Buffer.from([0x01]));
    expect(decoded.get("id")?.toString()).toBe("tun-1234");
    expect(decoded.get("dt")).toEqual(Buffer.alloc(257, 0xab));
    expect(decoded.get("_")).toEqual(Buffer.alloc(0));
  });
});

describe("suo5 frame codec", () => {
  it("round-trips a frame", () => {
    const data = marshalSuo5Map([["dt", Buffer.from("identifier-xyz")]]);
    const frame = marshalFrameBase64(data);
    // header is exactly 8 base64url chars, data section contains no padding
    expect(frame.toString("latin1")).toMatch(/^[A-Za-z0-9\-_]+$/);
    const parsed = unmarshalFrameBase64(frame);
    expect(parsed.data).toEqual(data);
    expect(parsed.next).toBe(frame.length);
  });

  it("parses two concatenated frames", () => {
    const d1 = marshalSuo5Map([["dt", Buffer.from("first")]]);
    const d2 = marshalSuo5Map([["dt", Buffer.from("second-frame")]]);
    const buf = Buffer.concat([marshalFrameBase64(d1), marshalFrameBase64(d2)]);
    const f1 = unmarshalFrameBase64(buf, 0);
    const f2 = unmarshalFrameBase64(buf, f1.next);
    expect(unmarshalSuo5Map(f1.data).get("dt")?.toString()).toBe("first");
    expect(unmarshalSuo5Map(f2.data).get("dt")?.toString()).toBe("second-frame");
    expect(f2.next).toBe(buf.length);
  });

  it("rejects truncated frames", () => {
    const frame = marshalFrameBase64(marshalSuo5Map([["dt", Buffer.from("abc")]]));
    expect(() => unmarshalFrameBase64(frame.subarray(0, 4))).toThrow("truncated");
    expect(() => unmarshalFrameBase64(frame.subarray(0, frame.length - 2))).toThrow("truncated");
  });
});

// ---------- integration: testSuo5 against faithful Node mock servers ----------

const V2_GATE = "v2gatevalue";
const V1_GATE = "v1gatevalue";

function newDataFrame(id: Buffer | undefined, dt: Buffer): Buffer {
  return marshalFrameBase64(
    marshalSuo5Map([
      ["ac", Buffer.from([0x01])],
      ["dt", dt],
      ["id", id ?? Buffer.from("")],
    ]),
  );
}

function startMock(): Promise<Server> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const ua = req.headers["user-agent"] ?? "";

      if (req.url === "/suo5v2") {
        // port of the zema1/suo5.jsp handshake (classic branch), gate included
        if (!ua.includes(V2_GATE)) {
          res.writeHead(200).end();
          return;
        }
        try {
          const frame = unmarshalFrameBase64(body, 0);
          const map = unmarshalSuo5Map(frame.data);
          if (map.get("m")?.[0] !== 0x00) throw new Error("not a checking request");
          const sid = randomString(16);
          const out = Buffer.concat([
            newDataFrame(map.get("id"), map.get("dt")!),
            newDataFrame(map.get("id"), Buffer.from(sid)),
          ]);
          res.writeHead(200, { "Content-Type": "text/html" }).end(out);
        } catch {
          res.writeHead(200).end();
        }
        return;
      }

      if (req.url === "/suo5v1") {
        if (req.headers["content-type"] === "application/plain" && ua.includes(V1_GATE)) {
          res.writeHead(200).end(body.subarray(0, 32));
        } else {
          res.writeHead(200).end();
        }
        return;
      }

      if (req.url === "/404") {
        res.writeHead(404, { "Content-Type": "text/html" }).end("<html>not found</html>");
        return;
      }

      res.writeHead(200).end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

describe("testSuo5", () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    server = await startMock();
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  it("completes the v2 handshake and reports the session id", async () => {
    const result = await testSuo5(`${base}/suo5v2`, { headerValue: V2_GATE });
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/suo5 v2 handshake ok \(session [A-Za-z0-9]{16}/);
  });

  it("falls back to the v1 echo in auto mode", async () => {
    const result = await testSuo5(`${base}/suo5v1`, { headerValue: V1_GATE });
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/v1 full-duplex echo ok/);
  });

  it("respects --suo5-mode: v2 does not fall back to v1", async () => {
    const result = await testSuo5(`${base}/suo5v1`, { headerValue: V1_GATE, mode: "v2" });
    expect(result.ok).toBe(false);
  });

  it("fails without the gate header", async () => {
    const v2 = await testSuo5(`${base}/suo5v2`);
    expect(v2.ok).toBe(false);
    const v1 = await testSuo5(`${base}/suo5v1`);
    expect(v1.ok).toBe(false);
  });

  it("fails cleanly on a 404 page", async () => {
    const result = await testSuo5(`${base}/404`);
    expect(result.ok).toBe(false);
    expect(result.error).toContain("not a suo5 shell");
  });

  it("reports network errors", async () => {
    const result = await testSuo5("http://127.0.0.1:1/none", { timeoutMs: 2000 });
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });
});
