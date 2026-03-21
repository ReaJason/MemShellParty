export interface ShellConfig {
  server: string;
  serverVersion: string;
  shellTool: string;
  shellType: string;
  targetJreVersion?: string;
  debug?: boolean;
  byPassJavaModule?: boolean;
  obfuscate?: boolean;
  shrink?: boolean;
  probe?: boolean;
  lambdaSuffix?: boolean;
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

export interface CommandShellToolConfig {
  shellClassName?: string;
  paramName?: string;
  headerName?: string;
  headerValue?: string;
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

export interface ProxyShellToolConfig {
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

export interface LegacyPackerGroup {
  group: string;
  options: string[];
}

export interface PackerSchemaFieldOption {
  value: string;
  label: string;
}

export interface PackerSchemaField {
  key: string;
  type: string;
  required: boolean;
  defaultValue?: unknown;
  description?: string;
  descriptionI18nKey?: string;
  options?: PackerSchemaFieldOption[];
}

export interface PackerSchema {
  fields?: PackerSchemaField[];
  defaultConfig?: Record<string, unknown>;
}

export interface PackerEntry {
  name: string;
  outputKind?: string;
  categoryAnchor?: boolean;
  schema?: PackerSchema;
}

export interface PackerCategory {
  name: string;
  packers: PackerEntry[];
}

export type PackerConfig = Array<LegacyPackerGroup | PackerCategory | string>;

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
  injectorClassName: string;
  injectorSize: number;
  injectorBytesBase64Str: string;
  injectorHelperBytesBase64Str: string;
  injectorHelperSize: number;
  shellConfig: ShellConfig;
  shellToolConfig:
    | CommandShellToolConfig
    | GodzillaShellToolConfig
    | BehinderShellToolConfig
    | AntSwordShellToolConfig;
  injectorConfig: InjectorConfig;
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
  Command = "Command",
  AntSword = "AntSword",
  Suo5 = "Suo5",
  Suo5v2 = "Suo5v2",
  NeoreGeorg = "NeoreGeorg",
  Custom = "Custom",
  Proxy = "Proxy",
}
