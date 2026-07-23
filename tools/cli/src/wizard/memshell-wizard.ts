import { readFileSync } from "node:fs";

import { checkbox, confirm, input, select, Separator } from "@inquirer/prompts";

import type { MemPartyClient } from "../api/client.js";
import { JDK_VERSIONS } from "../core/jdk.js";
import type { MemShellOptions } from "../core/request-builder.js";

const JDK_CHOICES = [
  { name: "server default", value: "" },
  ...Object.entries(JDK_VERSIONS).map(([name, major]) => ({
    name: `${name} (${major})`,
    value: name,
  })),
];

function packerChoices(tree: { name: string; children: string[] }[]) {
  const choices: (Separator | { name: string; value: string })[] = [];
  for (const parent of tree) {
    choices.push(new Separator(`── ${parent.name} ──`));
    choices.push({ name: parent.name, value: parent.name });
    for (const child of parent.children) {
      choices.push({ name: `  ${child}`, value: child });
    }
  }
  return choices;
}

/** Drive an interactive prompt flow, returning options for buildMemShellRequest. */
export async function runMemShellWizard(client: MemPartyClient): Promise<MemShellOptions> {
  const [config, packerTree] = await Promise.all([client.getConfig(), client.getPackerTree()]);

  const server = await select({
    message: "Target server",
    choices: Object.keys(config).map((s) => ({ name: s, value: s })),
  });

  const tools = Object.keys(config[server]);
  const shellTool = await select({
    message: "Shell tool",
    choices: tools.map((t) => ({ name: t, value: t })),
  });

  const shellType = await select({
    message: "Shell type",
    choices: config[server][shellTool].map((t) => ({ name: t, value: t })),
  });

  const packer = await select({
    message: "Packer",
    choices: packerChoices(packerTree),
  });

  const opts: MemShellOptions = { server, shellTool, shellType, packer };

  // Tool-specific configuration.
  switch (shellTool) {
    case "Godzilla":
      opts.godzillaPass = await input({ message: "Godzilla pass", default: "pass" });
      opts.godzillaKey = await input({ message: "Godzilla key", default: "key" });
      break;
    case "Behinder":
      opts.behinderPass = await input({ message: "Behinder pass", default: "rebeyond" });
      break;
    case "AntSword":
      opts.antSwordPass = await input({ message: "AntSword pass", default: "ant" });
      break;
    case "Command": {
      opts.commandParamName = await input({ message: "Command param name", default: "cmd" });
      const cc = await client.getCommandConfigs();
      opts.encryptor = await select({
        message: "Encryptor",
        choices: cc.encryptors.map((e) => ({ name: e, value: e })),
      });
      opts.implementationClass = await select({
        message: "Implementation class",
        choices: cc.implementationClasses.map((e) => ({ name: e, value: e })),
      });
      const template = await input({ message: "Command template (optional, {command} placeholder)", default: "" });
      if (template) opts.commandTemplate = template;
      break;
    }
    case "Custom": {
      const file = await input({ message: "Path to custom .class file" });
      opts.shellClassBase64 = readFileSync(file).toString("base64");
      break;
    }
    default:
      break;
  }

  // Common header config (used by several tools).
  opts.headerName = await input({ message: "Header name", default: "User-Agent" });
  const headerValue = await input({ message: "Header value (optional)", default: "" });
  if (headerValue) opts.headerValue = headerValue;

  const shellClassName = await input({ message: "Shell class name (optional, random if empty)", default: "" });
  if (shellClassName) opts.shellClassName = shellClassName;

  opts.urlPattern = await input({ message: "URL pattern", default: "/*" });

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

  const confirmed = await confirm({ message: `Generate ${shellTool} ${shellType} for ${server} (${packer})?` });
  if (!confirmed) {
    throw new Error("Cancelled by user.");
  }

  return opts;
}
