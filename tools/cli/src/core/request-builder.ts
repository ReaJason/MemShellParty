import { randomInt } from "node:crypto";

import type {
  MemShellGenerateRequest,
  ProbeShellGenerateRequest,
} from "../api/types.js";
import { resolveJreVersion } from "./jdk.js";

/**
 * Packers that require a randomised Spring expression injector class name.
 * Ported from web/app/utils/transformer.ts.
 */
const SPRING_GZIP_JDK17_RELATED_PACKERS = new Set([
  "SpEL",
  "SpELSpringGzipJDK17",
  "OGNL",
  "OGNLSpringGzipJDK17",
  "JXPath",
  "JXPathSpringGzipJDK17",
]);

const UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CLASS_NAME_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function randomChar(chars: string): string {
  return chars[randomInt(chars.length)];
}

function generateSpringExpressionInjectorClassName(): string {
  const randomName = Array.from({ length: 5 }, () => randomChar(CLASS_NAME_LETTERS)).join("");
  return `org.springframework.expression.${randomChar(UPPERCASE_LETTERS)}${randomName}Util`;
}

/** Flat option set for building a memshell request (from flags or the wizard). */
export interface MemShellOptions {
  server: string;
  serverVersion?: string;
  shellTool: string;
  shellType: string;
  packer: string;

  jdk?: string | number;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
  lambdaSuffix?: boolean;
  probe?: boolean;

  shellClassName?: string;
  godzillaPass?: string;
  godzillaKey?: string;
  commandParamName?: string;
  commandTemplate?: string;
  behinderPass?: string;
  antSwordPass?: string;
  headerName?: string;
  headerValue?: string;
  shellClassBase64?: string;
  encryptor?: string;
  implementationClass?: string;

  urlPattern?: string;
  injectorClassName?: string;
  staticInitialize?: boolean;
}

export function buildMemShellRequest(opts: MemShellOptions): MemShellGenerateRequest {
  const injectorClassName = SPRING_GZIP_JDK17_RELATED_PACKERS.has(opts.packer)
    ? generateSpringExpressionInjectorClassName()
    : opts.injectorClassName;

  return {
    shellConfig: {
      server: opts.server,
      serverVersion: opts.serverVersion,
      shellTool: opts.shellTool,
      shellType: opts.shellType,
      targetJreVersion: resolveJreVersion(opts.jdk),
      debug: opts.debug,
      byPassJavaModule: opts.byPassJavaModule,
      shrink: opts.shrink,
      lambdaSuffix: opts.lambdaSuffix,
      probe: opts.probe,
    },
    shellToolConfig: {
      shellClassName: opts.shellClassName,
      godzillaPass: opts.godzillaPass,
      godzillaKey: opts.godzillaKey,
      commandParamName: opts.commandParamName,
      commandTemplate: opts.commandTemplate,
      behinderPass: opts.behinderPass,
      antSwordPass: opts.antSwordPass,
      headerName: opts.headerName,
      headerValue: opts.headerValue,
      shellClassBase64: opts.shellClassBase64,
      encryptor: opts.encryptor,
      implementationClass: opts.implementationClass,
    },
    injectorConfig: {
      injectorClassName,
      urlPattern: opts.urlPattern,
      staticInitialize: opts.staticInitialize,
    },
    packer: opts.packer,
  };
}

/** Flat option set for building a probe request. */
export interface ProbeOptions {
  probeMethod: string;
  probeContent: string;
  packer: string;

  shellClassName?: string;
  jdk?: string | number;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
  staticInitialize?: boolean;
  lambdaSuffix?: boolean;

  host?: string;
  seconds?: number;
  sleepServer?: string;
  server?: string;
  reqParamName?: string;
  commandTemplate?: string;
}

export function buildProbeRequest(opts: ProbeOptions): ProbeShellGenerateRequest {
  return {
    probeConfig: {
      probeMethod: opts.probeMethod,
      probeContent: opts.probeContent,
      shellClassName: opts.shellClassName,
      targetJreVersion: resolveJreVersion(opts.jdk),
      debug: opts.debug,
      byPassJavaModule: opts.byPassJavaModule,
      shrink: opts.shrink,
      staticInitialize: opts.staticInitialize,
      lambdaSuffix: opts.lambdaSuffix,
    },
    probeContentConfig: {
      host: opts.host,
      seconds: opts.seconds,
      sleepServer: opts.sleepServer,
      server: opts.server,
      reqParamName: opts.reqParamName,
      commandTemplate: opts.commandTemplate,
    },
    packer: opts.packer,
  };
}
