export interface BytecodeFormValues {
  inputMode: "base64" | "file";
  classBase64: string;
  fileClassBase64: string;
  fileName: string;
  packer: string;
  byPassJavaModule: boolean;
  staticInitialize: boolean;
  shrink: boolean;
  renamePackage: boolean;
  relocateFrom: string;
  relocateTo: string;
  entryMethodEnabled: boolean;
  entryMethod: string;
  newClassName: string;
  randomName: boolean;
  obfuscation: boolean;
  obfuscationOptions: string;
  probe: boolean;
  probeMethod: "ResponseBody" | "ResponseHeader";
  respHeaderName: string;
  server: string;
}

export interface BytecodeClassResponse {
  className: string;
  size: number;
  classBytesBase64Str: string;
}

export interface BytecodeTransformResponse extends BytecodeClassResponse {
  packResult: string;
}

export interface BytecodeResult extends BytecodeTransformResponse {
  packMethod: string;
}
