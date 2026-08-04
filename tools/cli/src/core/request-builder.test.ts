import { describe, expect, it } from "vitest";

import { buildMemShellRequest, buildProbeRequest } from "./request-builder.js";

describe("buildMemShellRequest", () => {
  it("maps flat options into the nested request shape", () => {
    const req = buildMemShellRequest({
      server: "Tomcat",
      shellTool: "Godzilla",
      shellType: "Listener",
      packer: "Base64",
      jdk: "java8",
      godzillaPass: "pass",
      godzillaKey: "key",
      headerName: "User-Agent",
      urlPattern: "/*",
      shrink: true,
      staticInitialize: true,
    });

    expect(req.shellConfig.server).toBe("Tomcat");
    expect(req.shellConfig.shellTool).toBe("Godzilla");
    expect(req.shellConfig.shellType).toBe("Listener");
    expect(req.shellConfig.targetJreVersion).toBe(52);
    expect(req.shellToolConfig.godzillaPass).toBe("pass");
    expect(req.shellToolConfig.godzillaKey).toBe("key");
    expect(req.injectorConfig.urlPattern).toBe("/*");
    expect(req.injectorConfig.staticInitialize).toBe(true);
    expect(req.packer).toBe("Base64");
  });

  it("keeps the provided injector class name for normal packers", () => {
    const req = buildMemShellRequest({
      server: "Tomcat",
      shellTool: "Command",
      shellType: "Filter",
      packer: "Base64",
      injectorClassName: "com.example.MyInjector",
    });
    expect(req.injectorConfig.injectorClassName).toBe("com.example.MyInjector");
  });

  it("generates a spring expression injector name for SpEL packers", () => {
    const req = buildMemShellRequest({
      server: "Tomcat",
      shellTool: "Command",
      shellType: "Filter",
      packer: "SpEL",
      injectorClassName: "ignored",
    });
    expect(req.injectorConfig.injectorClassName).toMatch(
      /^org\.springframework\.expression\.[A-Z][A-Za-z]{5}Util$/,
    );
  });

  it("leaves targetJreVersion undefined when no jdk is given", () => {
    const req = buildMemShellRequest({
      server: "Tomcat",
      shellTool: "Godzilla",
      shellType: "Listener",
      packer: "Base64",
    });
    expect(req.shellConfig.targetJreVersion).toBeUndefined();
  });
});

describe("buildProbeRequest", () => {
  it("maps DNSLog probe options", () => {
    const req = buildProbeRequest({
      probeMethod: "DNSLog",
      probeContent: "BasicInfo",
      packer: "Base64",
      host: "abc.dnslog.cn",
    });
    expect(req.probeConfig.probeMethod).toBe("DNSLog");
    expect(req.probeContentConfig.host).toBe("abc.dnslog.cn");
    expect(req.packer).toBe("Base64");
  });

  it("maps Sleep probe options and coerces seconds", () => {
    const req = buildProbeRequest({
      probeMethod: "Sleep",
      probeContent: "Server",
      packer: "Base64",
      sleepServer: "Tomcat",
      seconds: 5,
    });
    expect(req.probeContentConfig.sleepServer).toBe("Tomcat");
    expect(req.probeContentConfig.seconds).toBe(5);
  });
});
