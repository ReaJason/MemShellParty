export interface ShellConfig {
  server: string;
  shellTool: string;
  shellType: string;
  targetJreVersion?: string;
  debug?: boolean;
  byPassJavaModule?: boolean;
  obfuscate?: boolean;
}

export interface ShellToolConfig {
  shellClassName?: string;
  godzillaPass?: string;
  godzillaKey?: string;
  godzillaHeaderName?: string;
  godzillaHeaderValue?: string;
  commandParamName?: string;
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

export interface InjectorConfig {
  className?: string;
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

export interface PackerConfig {
  [packerName: string]: string;
}

export interface GenerateResponse {
  packResult: string;
  generateResult: GenerateResult;
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
  shellToolConfig: CommandShellToolConfig | GodzillaShellToolConfig;
  injectorConfig: InjectorConfig;
}
