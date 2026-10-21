import type { ObfuscationConfig, ObfuscationInfo } from "./memshell";

export type ProbeMethod = "ResponseBody" | "ResponseHeader" | "DNSLog" | "Sleep";

export type ProbeContent =
  | "BasicInfo"
  | "Server"
  | "OS"
  | "JDK"
  | "Bytecode"
  | "Command"
  | "ScriptEngine"
  | "Filter";

export interface ProbeConfig {
  probeMethod: string;
  probeContent: string;
  shellClassName?: string;
  targetJreVersion?: string;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
  staticInitialize?: boolean;
  lambdaSuffix?: boolean;
  obfuscation?: ObfuscationConfig;
}

export interface ProbeContentConfig {
  host?: string;
  seconds?: number;
  sleepServer?: string;
  server?: string;
  reqParamName?: string;
  commandTemplate?: string;
  respHeaderName?: string;
}

export interface DNSLogConfig {
  host: string;
}

export interface SleepConfig {
  server: string;
  sleepServer: string;
}

export interface ResponseConfig {
  server: string;
  reqParamName?: string;
  commandTemplate: string;
  respHeaderName?: string;
}

export interface PayloadFormValues {
  probeMethod: ProbeMethod;
  probeContent?: ProbeContent;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
  host?: string;
  server?: string;
  reqParamName?: string;
  commandTemplate?: string;
  respHeaderName?: string;
  sleepServer?: string;
  seconds?: number;
  packingMethod: string;
}

export interface ProbeShellGenerateResponse {
  probeShellResult: ProbeShellResult;
  packResult?: string;
}

export interface ProbeShellResult {
  shellClassName: string;
  shellSize: number;
  shellBytesBase64Str: string;
  probeConfig: ProbeConfig;
  probeContentConfig: DNSLogConfig | ResponseConfig | SleepConfig;
  obfuscationInfo?: ObfuscationInfo;
}
