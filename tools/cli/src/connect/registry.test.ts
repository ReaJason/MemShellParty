import { describe, expect, it } from "vitest";

import {
  getProtocol,
  protocolNames,
  requireProtocol,
  unsupportedMessage,
} from "./registry.js";

describe("protocol registry", () => {
  it("registers the three built-in tools plus mimic", () => {
    expect(protocolNames()).toEqual(["godzilla", "behinder", "suo5", "mimic"]);
  });

  it("filters protocol names by capability", () => {
    // suo5 is connect-only, mimic is exec-only in this pass
    expect(protocolNames("exec")).toEqual(["godzilla", "behinder", "mimic"]);
    expect(protocolNames("upload")).toEqual(["godzilla", "behinder"]);
    expect(protocolNames("download")).toEqual(["godzilla", "behinder"]);
  });

  it("exposes capabilities as optional methods", () => {
    expect(getProtocol("suo5")!.exec).toBeUndefined();
    expect(getProtocol("mimic")!.exec).toBeTypeOf("function");
    expect(getProtocol("mimic")!.upload).toBeUndefined();
    expect(getProtocol("godzilla")!.upload).toBeTypeOf("function");
  });

  it("requireProtocol names the available protocols on a typo", () => {
    expect(() => requireProtocol("godzila")).toThrow(/available: godzilla, behinder, suo5, mimic/);
  });

  it("unsupportedMessage names the protocol and the capability", () => {
    expect(unsupportedMessage(getProtocol("suo5")!, "exec")).toBe(
      "protocol 'suo5' does not support exec",
    );
  });
});
