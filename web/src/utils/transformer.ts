import { FormSchema } from "@/types/schema.ts";
import { InjectorConfig, ShellConfig, ShellToolConfig } from "@/types/shell.ts";

export function transformToPostData(formValue: FormSchema) {
  const shellConfig: ShellConfig = {
    server: formValue.server,
    serverVersion: formValue.serverVersion,
    shellTool: formValue.shellTool,
    shellType: formValue.shellType,
    debug: formValue.debug,
    targetJreVersion: formValue.targetJdkVersion,
    byPassJavaModule: formValue.bypassJavaModule,
    shrink: formValue.shrink,
  };
  const shellToolConfig: ShellToolConfig = {
    shellClassName: formValue.shellClassName,
    godzillaPass: formValue.godzillaPass,
    godzillaKey: formValue.godzillaKey,
    commandParamName: formValue.commandParamName,
    behinderPass: formValue.behinderPass,
    antSwordPass: formValue.antSwordPass,
    headerName: formValue.headerName,
    headerValue: formValue.headerValue,
    shellClassBase64: formValue.shellClassBase64,
    encryptor: formValue.encryptor,
    implementationClass: formValue.implementationClass,
  };

  const injectorConfig: InjectorConfig = {
    urlPattern: formValue.urlPattern,
    injectorClassName: formValue.injectorClassName,
  };
  return {
    shellConfig,
    shellToolConfig,
    injectorConfig,
    packer: formValue.packingMethod,
  };
}

/**
 * Generates a URL with the current form values as query parameters
 * @param values The form values
 * @returns A URL string with query parameters
 */
export function generateShareableUrl(values: FormSchema): string {
  const params = new URLSearchParams();

  // Helper function to add parameters only if they have non-default values
  const addParam = (key: string, value: any, defaultValue: any) => {
    if (value !== defaultValue) {
      params.append(key, String(value));
    }
  };

  // Add all form values to the URL parameters
  addParam("server", values.server, "Tomcat");
  addParam("targetJdkVersion", values.targetJdkVersion, "50");
  addParam("debug", values.debug, false);
  addParam("bypassJavaModule", values.bypassJavaModule, false);
  addParam("shellClassName", values.shellClassName, "");
  addParam("shellTool", values.shellTool, "Godzilla");
  addParam("shellType", values.shellType, "Listener");
  addParam("urlPattern", values.urlPattern, "/*");
  addParam("godzillaPass", values.godzillaPass, "pass");
  addParam("godzillaKey", values.godzillaKey, "key");
  addParam("commandParamName", values.commandParamName, "cmd");
  addParam("behinderPass", values.behinderPass, "pass");
  addParam("antSwordPass", values.antSwordPass, "ant");
  addParam("headerName", values.headerName, "User-Agent");
  addParam("headerValue", values.headerValue, "test");
  addParam("injectorClassName", values.injectorClassName, "");
  addParam("packingMethod", values.packingMethod, "Base64");
  addParam("shrink", values.shrink, false);
  addParam("shellClassBase64", values.shellClassBase64, "");

  // Return the current URL with the query parameters
  return `${window.location.origin}${window.location.pathname}?${params.toString()}`;
}
