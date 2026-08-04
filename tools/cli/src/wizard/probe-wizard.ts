import { checkbox, confirm, input, select } from "@inquirer/prompts";

import type { MemPartyClient } from "../api/client.js";
import { JDK_VERSIONS } from "../core/jdk.js";
import type { ProbeOptions } from "../core/request-builder.js";

const JDK_CHOICES = [
  { name: "server default", value: "" },
  ...Object.entries(JDK_VERSIONS).map(([name, major]) => ({ name: `${name} (${major})`, value: name })),
];

const PROBE_METHODS = ["ResponseBody", "DNSLog", "Sleep"];
const PROBE_CONTENTS = ["BasicInfo", "Server", "OS", "JDK", "Bytecode", "Command"];

export async function runProbeWizard(client: MemPartyClient): Promise<ProbeOptions> {
  const [config, packerTree] = await Promise.all([client.getConfig(), client.getPackerTree()]);
  const servers = Object.keys(config);

  const probeMethod = await select({
    message: "Probe method",
    choices: PROBE_METHODS.map((m) => ({ name: m, value: m })),
  });

  const probeContent = await select({
    message: "Probe content",
    choices: PROBE_CONTENTS.map((c) => ({ name: c, value: c })),
  });

  const packer = await select({
    message: "Packer",
    choices: packerTree.flatMap((p) => [
      { name: p.name, value: p.name },
      ...p.children.map((c) => ({ name: `  ${c}`, value: c })),
    ]),
  });

  const opts: ProbeOptions = { probeMethod, probeContent, packer };

  switch (probeMethod) {
    case "DNSLog":
      opts.host = await input({ message: "DNSLog host" });
      break;
    case "Sleep":
      opts.sleepServer = await select({
        message: "Sleep server",
        choices: servers.map((s) => ({ name: s, value: s })),
      });
      opts.seconds = Number(await input({ message: "Seconds", default: "5" }));
      break;
    case "ResponseBody":
      opts.server = await select({
        message: "Server",
        choices: servers.map((s) => ({ name: s, value: s })),
      });
      opts.reqParamName = await input({ message: "Request param name", default: "cmd" });
      opts.commandTemplate = await input({
        message: "Command template (optional, {command} placeholder)",
        default: "",
      });
      break;
    default:
      break;
  }

  const shellClassName = await input({ message: "Shell class name (optional)", default: "" });
  if (shellClassName) opts.shellClassName = shellClassName;

  const jdk = await select({ message: "Target JDK", choices: JDK_CHOICES });
  if (jdk) opts.jdk = jdk;

  const toggles = await checkbox({
    message: "Options",
    choices: [
      { name: "shrink bytecode", value: "shrink", checked: true },
      { name: "static initialize", value: "staticInitialize", checked: true },
      { name: "bypass Java module", value: "byPassJavaModule" },
      { name: "lambda suffix", value: "lambdaSuffix" },
      { name: "debug", value: "debug" },
    ],
  });
  opts.shrink = toggles.includes("shrink");
  opts.staticInitialize = toggles.includes("staticInitialize");
  opts.byPassJavaModule = toggles.includes("byPassJavaModule");
  opts.lambdaSuffix = toggles.includes("lambdaSuffix");
  opts.debug = toggles.includes("debug");

  const confirmed = await confirm({ message: `Generate ${probeMethod} probe (${packer})?` });
  if (!confirmed) throw new Error("Cancelled by user.");

  return opts;
}
