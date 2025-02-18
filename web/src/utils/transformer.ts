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
    commandParamName: formValue.commandParamName,
    behinderPass: formValue.behinderPass,
    antSwordPass: formValue.antSwordPass,
    headerName: formValue.headerName,
    headerValue: formValue.headerValue,
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
