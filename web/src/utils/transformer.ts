import { FormSchema } from "@/types/schema.ts";
import { InjectorConfig, ShellConfig, ShellToolConfig, ShellToolType } from "@/types/shell.ts";
import { TFunction } from "i18next";

export function customValidation(t: TFunction<"translation", undefined>, values: FormSchema) {
  if (values.shellType.endsWith("Servlet") && (values.urlPattern === "/*" || !values.urlPattern)) {
    throw new Error(t("tips.servletUrlPattern"));
  }

  if (values.shellType.endsWith("ControllerHandler") && (values.urlPattern === "/*" || !values.urlPattern)) {
    throw new Error(t("tips.controllerUrlPattern"));
  }

  if (
    (values.shellType === "HandlerMethod" || values.shellType === "HandlerFunction") &&
    (values.urlPattern === "/*" || !values.urlPattern)
  ) {
    throw new Error(t("tips.handlerUrlPattern"));
  }

  if (values.shellTool === ShellToolType.Custom && !values.shellClassBase64) {
    throw new Error(t("tips.customShellClass"));
  }
}

export function transformToPostData(formValue: FormSchema) {
  const shellConfig: ShellConfig = {
    server: formValue.server,
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
