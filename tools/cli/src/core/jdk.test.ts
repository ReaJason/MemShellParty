import { describe, expect, it } from "vitest";

import { resolveJreVersion } from "./jdk.js";

describe("resolveJreVersion", () => {
  it("returns undefined for empty input", () => {
    expect(resolveJreVersion(undefined)).toBeUndefined();
    expect(resolveJreVersion("")).toBeUndefined();
  });

  it("resolves friendly names", () => {
    expect(resolveJreVersion("java8")).toBe(52);
    expect(resolveJreVersion("JAVA17")).toBe(61);
    expect(resolveJreVersion("java21")).toBe(65);
  });

  it("resolves bare java numbers", () => {
    expect(resolveJreVersion("8")).toBe(52);
    expect(resolveJreVersion("11")).toBe(55);
  });

  it("passes through raw class-file major versions", () => {
    expect(resolveJreVersion("52")).toBe(52);
    expect(resolveJreVersion(61)).toBe(61);
  });

  it("throws on invalid input", () => {
    expect(() => resolveJreVersion("banana")).toThrow(/Invalid JDK version/);
  });
});
