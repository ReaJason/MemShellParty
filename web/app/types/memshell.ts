export interface ObfuscationConfig {
  enabled: boolean;
  options?: Record<string, unknown>;
}

export const HEADER_PAYLOAD_WARNING_THRESHOLD = 4096;

export interface ObfuscationInfo {
  enabled: boolean;
  originalShellSize?: number;
  obfuscatedShellSize?: number;
  originalInjectorSize?: number;
  obfuscatedInjectorSize?: number;
  packedPayloadSize?: number;
  headerPayloadTooLarge?: boolean;
}

export interface ShellConfig {
  server: string;
  serverVersion: string;
  shellTool: string;
  shellType: string;
  targetJreVersion?: string;
  debug?: boolean;
  byPassJavaModule?: boolean;
  obfuscation?: ObfuscationConfig;
  shrink?: boolean;
  probe?: boolean;
  lambdaSuffix?: boolean;
}

export interface ShellToolConfig {
  shellClassName?: string;
  pass?: string;
  key?: string;
  paramName?: string;
  template?: string;
  headerName?: string;
  headerValue?: string;
  shellClassBase64?: string;
  encryptor?: string;
  implementationClass?: string;
}

export interface ShellToolConfigParam {
  name: string;
  type: "string" | "enum";
  options: Array<string>;
  group: "BASIC" | "ADVANCED";
}

export interface ShellToolConfigEntry {
  tool: string;
  params: Array<ShellToolConfigParam>;
}

/**
 * /api/config/obfuscation/options 的单项：与后端 OptionRegistry.OptionMeta.toMap() 对应，
 * min/max 仅 integer 类型携带，defaultValue 为 null 表示运行时自动生成（如 aesKey）。
 */
export interface ObfuscationOptionEntry {
  name: string;
  type: "boolean" | "integer" | "string" | "list";
  defaultValue: unknown;
  description: string;
  min?: number;
  max?: number;
}

export interface CommandShellToolConfig {
  shellClassName?: string;
  paramName?: string;
}

export interface GodzillaShellToolConfig {
  shellClassName?: string;
  pass?: string;
  key?: string;
  headerName?: string;
  headerValue?: string;
}

export interface BehinderShellToolConfig {
  shellClassName?: string;
  pass?: string;
  headerName?: string;
  headerValue?: string;
}

export interface Suo5ShellToolConfig {
  shellClassName?: string;
  headerName?: string;
  headerValue?: string;
}

export interface AntSwordShellToolConfig {
  shellClassName?: string;
  pass?: string;
  headerName?: string;
  headerValue?: string;
}

export interface NeoreGeorgShellToolConfig {
  shellClassName?: string;
  headerName?: string;
  headerValue?: string;
}

export interface InjectorConfig {
  injectorClassName?: string;
  injectorHelperClassName?: string;
  classInheritance?: string;
  urlPattern?: string;
  staticInitialize?: boolean;
}

export interface ConfigResponseType {
  servers: ServerConfig;
  core: MainConfig;
  packers: PackerConfig;
}

export interface ServerConfig {
  [serverName: string]: Array<string>;
}

export interface MainConfig {
  [serverName: string]: {
    [toolName: string]: string[];
  };
}

export interface PackerOption {
  name: string;
  children: string[];
}

export type PackerConfig = Array<PackerOption>;

export interface MemShellGenerateResponse {
  memShellResult: MemShellResult;
  packResult?: string;
}

export interface APIErrorResponse {
  error: string;
}

export interface MemShellResult {
  shellClassName: string;
  shellSize: number;
  shellBytesBase64Str: string;
  helperClassName?: string;
  helperSize?: number;
  helperBytesBase64Str?: string;
  injectorClassName: string;
  injectorSize: number;
  injectorBytesBase64Str: string;
  shellConfig: ShellConfig;
  shellToolConfig:
    | CommandShellToolConfig
    | GodzillaShellToolConfig
    | BehinderShellToolConfig
    | AntSwordShellToolConfig;
  injectorConfig: InjectorConfig;
  obfuscationInfo?: ObfuscationInfo;
}

export const JDKVersion = [
  { name: "Java6", value: "50" },
  { name: "Java8", value: "52" },
  { name: "Java9", value: "53" },
  { name: "Java11", value: "55" },
  { name: "Java17", value: "61" },
  { name: "Java21", value: "65" },
];

export enum ShellToolType {
  Behinder = "Behinder",
  Godzilla = "Godzilla",
  GodzillaSession = "GodzillaSession",
  Command = "Command",
  AntSword = "AntSword",
  Suo5 = "Suo5",
  NeoreGeorg = "NeoreGeorg",
  Custom = "Custom",
  Proxy = "Proxy",
}
