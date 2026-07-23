import { describe, expect, it } from "vitest";

import { ECHO_CLASS_BYTES } from "./assets.js";
import { injectStringConstant, readStringConstant } from "./classfile.js";

describe("injectStringConstant", () => {
  it("adds a ConstantValue to a field that has none", () => {
    expect(readStringConstant(ECHO_CLASS_BYTES, "content")).toBeNull();

    const value = `test-${"x".repeat(60)}-content`;
    const patched = injectStringConstant(ECHO_CLASS_BYTES, "content", value);

    expect(readStringConstant(patched, "content")).toBe(value);
    // magic / minor / major untouched (pool count at offset 8 grows by design)
    expect(patched.readUInt32BE(0)).toBe(0xcafebabe);
    expect(patched.subarray(4, 8)).toEqual(ECHO_CLASS_BYTES.subarray(4, 8));
  });

  it("handles unicode values and repeated injection", () => {
    const patched1 = injectStringConstant(ECHO_CLASS_BYTES, "content", "第一次");
    expect(readStringConstant(patched1, "content")).toBe("第一次");
    const patched2 = injectStringConstant(patched1, "content", "second");
    expect(readStringConstant(patched2, "content")).toBe("second");
  });

  it("encodes supplementary characters as modified UTF-8 (surrogate 3-byte pairs)", () => {
    // plain 4-byte UTF-8 in a CONSTANT_Utf8 entry makes the JVM reject the
    // class — emoji must be stored as two 3-byte surrogate sequences
    const value = "日志-😀-文件";
    const patched = injectStringConstant(ECHO_CLASS_BYTES, "content", value);
    expect(readStringConstant(patched, "content")).toBe(value);
    // 😀 = U+1F600 -> ED A0 BD ED B8 80 in modified UTF-8
    expect(patched.includes(Buffer.from([0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]))).toBe(true);
    // ...and must NOT contain the plain 4-byte form F0 9F 98 80
    expect(patched.includes(Buffer.from([0xf0, 0x9f, 0x98, 0x80]))).toBe(false);
  });

  it("does not touch other fields", () => {
    const patched = injectStringConstant(ECHO_CLASS_BYTES, "content", "abc123");
    expect(readStringConstant(patched, "payloadBody")).toBeNull();
  });

  it("rejects non-class input and unknown fields", () => {
    expect(() => injectStringConstant(Buffer.from("nope"), "content", "x")).toThrow(
      "not a Java class file",
    );
    expect(() => injectStringConstant(ECHO_CLASS_BYTES, "noSuchField", "x")).toThrow("not found");
  });
});
