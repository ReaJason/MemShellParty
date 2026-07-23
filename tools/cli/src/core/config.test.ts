import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { DEFAULT_API_URL, resolveApiUrl } from "./config.js";

// A nonexistent dir on an existing drive: the .mempartyrc read fails fast with
// ENOENT (an unmapped drive letter like Z: would instead hang for ~15s on Windows).
const NO_RC_HOME = join(tmpdir(), "memparty-no-rc-home-987654");

describe("resolveApiUrl", () => {
  it("prefers the --api flag above everything", () => {
    const url = resolveApiUrl({
      flag: "http://flag.example",
      env: { MEMPARTY_API_URL: "http://env.example" },
      home: NO_RC_HOME,
    });
    expect(url).toBe("http://flag.example");
  });

  it("falls back to the env var when no flag", () => {
    const url = resolveApiUrl({
      env: { MEMPARTY_API_URL: "http://env.example" },
      home: NO_RC_HOME,
    });
    expect(url).toBe("http://env.example");
  });

  it("falls back to the default public site", () => {
    const url = resolveApiUrl({ env: {}, home: NO_RC_HOME });
    expect(url).toBe(DEFAULT_API_URL);
  });

  it("ignores blank flag/env values", () => {
    const url = resolveApiUrl({ flag: "   ", env: { MEMPARTY_API_URL: "" }, home: NO_RC_HOME });
    expect(url).toBe(DEFAULT_API_URL);
  });
});
