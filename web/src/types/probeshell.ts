export type ProbeMethod = "ResponseBody" | "DNSLog" | "Sleep";

export type ProbeContent =
  | "BasicInfo"
  | "Server"
  | "OS"
  | "JDK"
  | "Bytecode"
  | "Command";

export interface ProbeConfig {
  probeMethod: string;
  probeContent: string;
  shellClassName?: string;
  targetJreVersion?: string;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
}

export interface ProbeContentConfig {
  host?: string;
  seconds?: number;
  sleepServer?: string;
  server?: string;
  reqParamName?: string;
  reqHeaderName?: string;
}

export interface DNSLogConfig {
  host: string;
}

export interface SleepConfig {
  server: string;
  sleepServer: string;
}

export interface ResponseBodyConfig {
  server: string;
  reqParamName: string;
  reqHeaderName: string;
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
  reqHeaderName?: string;
  sleepServer?: string;
  seconds?: number;
  packingMethod: string;
}

export interface ProbeShellGenerateResponse {
  probeShellResult: ProbeShellResult;
  packResult?: string;
  allPackResults?: Map<string, string>;
}

export interface ProbeShellResult {
  shellClassName: string;
  shellSize: number;
  shellBytesBase64Str: string;
  probeConfig: ProbeConfig;
  probeContentConfig: DNSLogConfig | ResponseBodyConfig | SleepConfig;
}
