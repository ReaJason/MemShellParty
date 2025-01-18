import { FormSchema } from "@/types/schema.ts";
import { InjectorConfig, ShellConfig, ShellToolConfig } from "@/types/shell.ts";

export function transformToPostData(formValue: FormSchema) {
  const shellConfig: ShellConfig = {
    server: formValue.server,
    shellTool: formValue.shellTool,
    shellType: formValue.shellType,
    debug: formValue.debug,
    targetJreVersion: formValue.targetJdkVersion,
    byPassJavaModule: formValue.bypassJavaModule,
  };
  const shellToolConfig: ShellToolConfig = {
    shellClassName: formValue.shellClassName,
    godzillaPass: formValue.godzillaPass,
    godzillaKey: formValue.godzillaKey,
    godzillaHeaderName: formValue.godzillaHeaderName,
    godzillaHeaderValue: formValue.godzillaHeaderValue,
    commandParamName: formValue.commandParamName,
    behinderPass: formValue.behinderPass,
    behinderHeaderName: formValue.behinderHeaderName,
    behinderHeaderValue: formValue.behinderHeaderValue,
  };

  const injectorConfig: InjectorConfig = {
    urlPattern: formValue.urlPattern,
    className: formValue.injectorClassName,
  };
  return {
    shellConfig,
    shellToolConfig,
    injectorConfig,
    packer: formValue.packingMethod,
  };
}
