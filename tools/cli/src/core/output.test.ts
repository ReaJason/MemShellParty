import { describe, expect, it, vi } from "vitest";

import { emitPayload, shouldDecode } from "./output.js";

describe("shouldDecode", () => {
  it("honours an explicit decode flag", () => {
    expect(shouldDecode({ decode: true, outFile: "x.txt" })).toBe(true);
    expect(shouldDecode({ decode: false, outFile: "x.jar" })).toBe(false);
  });

  it("infers from binary file extensions", () => {
    expect(shouldDecode({ outFile: "shell.jar" })).toBe(true);
    expect(shouldDecode({ outFile: "Shell.CLASS" })).toBe(true);
    expect(shouldDecode({ outFile: "payload.jsp" })).toBe(false);
  });

  it("defaults to false for stdout", () => {
    expect(shouldDecode({})).toBe(false);
  });
});

describe("emitPayload", () => {
  it("writes a raw string to stdout with a trailing newline", () => {
    const writeStdout = vi.fn();
    const result = emitPayload("hello", {}, { writeStdout });
    expect(writeStdout).toHaveBeenCalledWith("hello\n");
    expect(result.destination).toBe("stdout");
    expect(result.decoded).toBe(false);
  });

  it("writes a raw string to a file", () => {
    const writeFile = vi.fn();
    const result = emitPayload("payloadtext", { outFile: "out.jsp" }, { writeFile });
    expect(writeFile).toHaveBeenCalledWith("out.jsp", "payloadtext");
    expect(result.destination).toBe("out.jsp");
    expect(result.decoded).toBe(false);
  });

  it("base64-decodes when writing a .jar file", () => {
    const writeFile = vi.fn();
    const original = Buffer.from("binary-bytes");
    const b64 = original.toString("base64");
    const result = emitPayload(b64, { outFile: "shell.jar" }, { writeFile });

    expect(writeFile).toHaveBeenCalledTimes(1);
    const written = writeFile.mock.calls[0][1] as Buffer;
    expect(Buffer.isBuffer(written)).toBe(true);
    expect(written.equals(original)).toBe(true);
    expect(result.decoded).toBe(true);
    expect(result.size).toBe(original.length);
  });

  it("does not decode when --no-decode is set for a .jar file", () => {
    const writeFile = vi.fn();
    emitPayload("not-base64", { outFile: "shell.jar", decode: false }, { writeFile });
    expect(writeFile).toHaveBeenCalledWith("shell.jar", "not-base64");
  });
});
