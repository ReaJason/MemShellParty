/**
 * Type definitions mirroring the MemShellParty backend DTOs.
 * Source of truth: boot/src/main/java/com/reajason/javaweb/boot/{dto,vo,controller}
 */

// ---------- Shared request pieces ----------

export interface ShellConfig {
  server: string;
  serverVersion?: string;
  shellTool: string;
  shellType: string;
  /** Java class-file major version, e.g. 50 (Java6), 52 (Java8), 61 (Java17). */
  targetJreVersion?: number;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
  lambdaSuffix?: boolean;
  probe?: boolean;
}

export interface ShellToolConfig {
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
}

export interface InjectorConfig {
  injectorClassName?: string;
  urlPattern?: string;
  staticInitialize?: boolean;
}

export interface MemShellGenerateRequest {
  shellConfig: ShellConfig;
  shellToolConfig: ShellToolConfig;
  injectorConfig: InjectorConfig;
  /** Packer name, e.g. "Base64", "Jar", "JSP". */
  packer: string;
}

// ---------- Shared response pieces ----------

export interface MemShellResult {
  shellClassName: string;
  shellSize: number;
  shellBytesBase64Str: string;
  injectorClassName: string;
  injectorSize: number;
  injectorBytesBase64Str: string;
  shellConfig: ShellConfig;
  shellToolConfig: ShellToolConfig;
  injectorConfig: InjectorConfig;
}

export interface MemShellGenerateResponse {
  memShellResult: MemShellResult;
  packResult?: string;
  allPackResults?: Record<string, string>;
}

// ---------- Probe ----------

export type ProbeMethod = "ResponseBody" | "DNSLog" | "Sleep";
export type ProbeContent = "BasicInfo" | "Server" | "OS" | "JDK" | "Bytecode" | "Command";

export interface ProbeConfig {
  probeMethod: string;
  probeContent: string;
  shellClassName?: string;
  targetJreVersion?: number;
  debug?: boolean;
  byPassJavaModule?: boolean;
  shrink?: boolean;
  staticInitialize?: boolean;
  lambdaSuffix?: boolean;
}

export interface ProbeContentConfig {
  host?: string;
  seconds?: number;
  sleepServer?: string;
  server?: string;
  reqParamName?: string;
  commandTemplate?: string;
}

export interface ProbeShellGenerateRequest {
  probeConfig: ProbeConfig;
  probeContentConfig: ProbeContentConfig;
  packer: string;
}

export interface ProbeShellResult {
  shellClassName: string;
  shellSize: number;
  shellBytesBase64Str: string;
  probeConfig: ProbeConfig;
  probeContentConfig: ProbeContentConfig;
}

export interface ProbeShellGenerateResponse {
  probeShellResult: ProbeShellResult;
  packResult?: string;
  allPackResults?: Record<string, string>;
}

// ---------- Config endpoints ----------

/** server name -> supported shell types */
export type ServerConfig = Record<string, string[]>;

/** server name -> { shell tool -> supported shell types } */
export type MainConfig = Record<string, Record<string, string[]>>;

export interface PackerOption {
  name: string;
  children: string[];
}
export type PackerTree = PackerOption[];

export interface CommandConfigVO {
  encryptors: string[];
  implementationClasses: string[];
}

export interface VersionInfo {
  currentVersion: string;
  latestVersion: string;
  hasUpdate?: boolean;
}

export interface ApiErrorResponse {
  error: string;
}
