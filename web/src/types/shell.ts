export interface ShellConfig {
  server: string;
  shellTool: string;
  shellType: string;
  targetJreVersion?: string;
  debug?: boolean;
  byPassJavaModule?: boolean;
  obfuscate?: boolean;
  shrink?: boolean;
}

export interface ShellToolConfig {
  shellClassName?: string;
  godzillaPass?: string;
  godzillaKey?: string;
  commandParamName?: string;
  behinderPass?: string;
  antSwordPass?: string;
  headerName?: string;
  headerValue?: string;
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

export interface InjectorConfig {
  injectorClassName?: string;
  classInheritance?: string;
  urlPattern?: string;
}

export interface ConfigResponseType {
  servers: string[];
  core: MainConfig;
  packers: PackerConfig;
}

export interface MainConfig {
  [serverName: string]: {
    [toolName: string]: string[];
  };
}

export type PackerConfig = Array<string>;

export interface GenerateResponse {
  generateResult: GenerateResult;
  packResult?: string;
  allPackResults?: Map<string, string>;
}

export interface APIErrorResponse {
  error: string;
}

export interface GenerateResult {
  shellClassName: string;
  shellSize: number;
  shellBytesBase64Str: string;
  injectorClassName: string;
  injectorSize: number;
  injectorBytesBase64Str: string;
  shellConfig: ShellConfig;
  shellToolConfig: CommandShellToolConfig | GodzillaShellToolConfig | BehinderShellToolConfig | AntSwordShellToolConfig;
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
  NeoreGeorg = "NeoreGeorg",
}
