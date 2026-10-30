import type {
  InjectorConfig,
  ObfuscationConfig,
  ShellConfig,
  ShellToolConfig,
  ShellToolConfigEntry,
} from "@/types/memshell";
import type { ProbeConfig, ProbeContentConfig } from "@/types/probeshell";
import type { MemShellFormSchema, ProbeShellFormSchema } from "@/types/schema";

import { usesRequestParam } from "@/lib/probe-config";

/**
 * 混淆选项：key=value 多行文本 → options 对象（与桌面端 OptionRegistry.parseFromText 同格式）。
 * 空行与 #、// 注释忽略；值保持字符串，由后端 OptionRegistry 统一做类型与范围校验。
 */
function buildObfuscation(enabled?: boolean, optionsText?: string): ObfuscationConfig {
  if (!enabled) {
    return { enabled: false };
  }
  const text = optionsText?.trim();
  if (!text) {
    return { enabled: true, options: {} };
  }
  const options: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      throw new Error(`Invalid obfuscation option line (expected key=value): ${trimmed}`);
    }
    options[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return { enabled: true, options };
}

export function restoreMemShellFormValues(formValue: MemShellFormSchema): MemShellFormSchema {
  return {
    ...formValue,
    obfuscationScope: formValue.obfuscationScope ?? "ALL",
  };
}

export function transformToPostData(
  formValue: MemShellFormSchema,
  shellToolConfigs?: Array<ShellToolConfigEntry>,
) {
  const shellConfig: ShellConfig = {
    server: formValue.server,
    serverVersion: formValue.serverVersion,
    shellTool: formValue.shellTool,
    shellType: formValue.shellType,
    debug: formValue.debug,
    targetJreVersion: formValue.targetJdkVersion,
    byPassJavaModule: formValue.byPassJavaModule,
    shrink: formValue.shrink,
    lambdaSuffix: formValue.lambdaSuffix,
    probe: formValue.probe
      ? {
          probeMethod: formValue.probeMethod || "ResponseBody",
          probeContent: "Bytecode",
          respHeaderName:
            formValue.probeMethod === "ResponseHeader" ? formValue.respHeaderName : undefined,
        }
      : undefined,
    obfuscation: buildObfuscation(formValue.obfuscation, formValue.obfuscationOptions),
    obfuscationScope: formValue.obfuscationScope ?? "ALL",
  };
  // Only the current shell tool's own params (per the config catalog) plus shellClassName may be
  // sent: values left over from another tool are rejected by the backend.
  const shellToolConfig: ShellToolConfig = {
    shellClassName: formValue.shellClassName,
  };
  const shellToolParams = shellToolConfigs?.find(
    (config) => config.tool === formValue.shellTool,
  )?.params;
  for (const param of shellToolParams ?? []) {
    const value = formValue[param.name as keyof MemShellFormSchema];
    if (typeof value === "string" && value !== "") {
      shellToolConfig[param.name as keyof ShellToolConfig] = value;
    }
  }

  const injectorConfig: InjectorConfig = {
    urlPattern: formValue.urlPattern,
    // SpringGzipJDK17 系打包方式的 org.springframework.expression 类名由服务端用词表补齐，
    // 这里不再生成随机大小写字母
    injectorClassName: formValue.injectorClassName,
    staticInitialize: formValue.staticInitialize,
  };
  return {
    shellConfig,
    shellToolConfig,
    injectorConfig,
    packer: formValue.packingMethod,
  };
}

export function transformToProbePostData(formValue: ProbeShellFormSchema) {
  const probeConfig: ProbeConfig = {
    probeMethod: formValue.probeMethod,
    probeContent: formValue.probeContent,
    shellClassName: formValue.shellClassName,
    shrink: formValue.shrink,
    debug: formValue.debug,
    byPassJavaModule: formValue.byPassJavaModule,
    staticInitialize: formValue.staticInitialize,
    lambdaSuffix: formValue.lambdaSuffix,
    obfuscation: buildObfuscation(formValue.obfuscation, formValue.obfuscationOptions),
  };
  const probeContentConfig: ProbeContentConfig = {
    host: formValue.host,
    seconds: formValue.seconds,
    sleepServer: formValue.sleepServer,
    server: formValue.server,
    reqParamName: usesRequestParam(formValue.probeContent, formValue.server)
      ? formValue.reqParamName
      : undefined,
    commandTemplate: formValue.commandTemplate,
    respHeaderName: formValue.respHeaderName,
  };

  return {
    probeConfig,
    probeContentConfig,
    packer: formValue.packingMethod,
  };
}

/**
 * Generates a URL with the current form values as query parameters
 * @param values The form values
 * @returns A URL string with query parameters
 */
export function generateShareableUrl(values: MemShellFormSchema): string {
  const params = new URLSearchParams();

  // Helper function to add parameters only if they have non-default values
  const addParam = (key: string, value: unknown, defaultValue: unknown) => {
    if (value !== defaultValue) {
      params.append(key, String(value));
    }
  };

  // Add all form values to the URL parameters
  addParam("server", values.server, "Tomcat");
  addParam("targetJdkVersion", values.targetJdkVersion, "50");
  addParam("debug", values.debug, false);
  addParam("byPassJavaModule", values.byPassJavaModule, false);
  addParam("shellClassName", values.shellClassName, "");
  addParam("shellTool", values.shellTool, "Godzilla");
  addParam("shellType", values.shellType, "Listener");
  addParam("urlPattern", values.urlPattern, "/*");
  addParam("pass", values.pass, "pass");
  addParam("key", values.key, "key");
  addParam("paramName", values.paramName, "cmd");
  addParam("headerName", values.headerName, "User-Agent");
  addParam("headerValue", values.headerValue, "test");
  addParam("injectorClassName", values.injectorClassName, "");
  addParam("packingMethod", values.packingMethod, "DefaultBase64");
  addParam("shrink", values.shrink, false);
  addParam("shellClassBase64", values.shellClassBase64, "");

  // Return the current URL with the query parameters
  return `${window.location.origin}${window.location.pathname}?${params.toString()}`;
}
