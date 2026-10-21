import type { MemShellFormSchema } from "@/types/schema";

import { ArrowUpRightIcon, PackageIcon, ServerIcon } from "lucide-react";
import { useCallback, useEffect, useMemo } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { BytecodeOptions } from "@/components/bytecode-config-card";
import { ConfigLoadError } from "@/components/config-load-error";
import { Field, FieldContent, FieldLabel } from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tabs } from "@/components/ui/tabs";
import {
  type MainConfig,
  type PackerConfig,
  type ShellToolConfigEntry,
  ShellToolType,
} from "@/types/memshell";

import { Spinner } from "../ui/spinner";
import { JREVersionFormField } from "./jreversion-field";
import { PackageConfigFields } from "./package-config-fields";
import { ServerVersionFormField } from "./serverversion-field";
import { ShellTypeFormField } from "./shelltype-field";
import CustomTabContent from "./tabs/custom-tab";
import { ShellToolTabContent } from "./tabs/shelltool-tab";

/**
 * 切工具时清空全部工具参数（目录里所有工具的字段都要清，避免跨工具残留），
 * 再按新工具回填：`pass` 是密码类工具共用的参数名，两边都有就留着省得重填。
 *
 * <p>其余参数一律留空，由后端按各工具 config 的 builder 默认值兜底 —— 显式填一个
 * "User-Agent" 反而会把 NeoreGeorg 这类默认值不同的工具写坏。
 */
const clearToolParams = (
  form: UseFormReturn<MemShellFormSchema>,
  shellToolConfigs: Array<ShellToolConfigEntry> | undefined,
  nextTool: string,
) => {
  const pass = form.getValues("pass");
  const paramNames = new Set(
    (shellToolConfigs ?? []).flatMap((config) => config.params.map((param) => param.name)),
  );
  for (const name of paramNames) {
    form.setValue(name as keyof MemShellFormSchema, "");
  }
  if (pass && declaresParam(shellToolConfigs, nextTool, "pass")) {
    form.setValue("pass", pass);
  }
};

const declaresParam = (
  shellToolConfigs: Array<ShellToolConfigEntry> | undefined,
  tool: string,
  param: string,
) => shellToolConfigs?.some((c) => c.tool === tool && c.params.some((p) => p.name === param));

export default function MainConfigPanel({
  mainConfig,
  shellToolConfigs,
  packerConfig,
  form,
  configError,
  isConfigRetrying,
  onRetryConfig,
  packerConfigError,
  isPackerRetrying,
  onRetryPacker,
}: Readonly<{
  mainConfig: MainConfig | undefined;
  shellToolConfigs: Array<ShellToolConfigEntry> | undefined;
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
  configError: Error | null;
  isConfigRetrying: boolean;
  onRetryConfig: () => void;
  packerConfigError: Error | null;
  isPackerRetrying: boolean;
  onRetryPacker: () => void;
}>) {
  const { t } = useTranslation(["common", "memshell"]);

  const server = useWatch({
    control: form.control,
    name: "server",
  });

  const shellTool = useWatch({
    control: form.control,
    name: "shellTool",
  });

  const serverToolMap = useMemo(() => {
    if (!mainConfig || !server) {
      return undefined;
    }
    return mainConfig[server];
  }, [mainConfig, server]);

  const serverOptions = useMemo(() => Object.keys(mainConfig ?? {}), [mainConfig]);

  const shellTools = useMemo(() => {
    if (!serverToolMap) {
      return [];
    }
    const tools = Object.keys(serverToolMap).map((tool) => tool as ShellToolType);
    return Array.from(new Set([...tools, ShellToolType.Custom]));
  }, [serverToolMap]);

  const customShellTypes = useMemo(() => {
    if (!serverToolMap) {
      return [];
    }
    return Array.from(new Set(Object.values(serverToolMap).flat()));
  }, [serverToolMap]);

  const shellTypes = useMemo(() => {
    if (!serverToolMap || !server) {
      return [];
    }
    if (shellTool === ShellToolType.Custom) {
      return customShellTypes;
    }
    return serverToolMap[shellTool] ?? [];
  }, [customShellTypes, server, serverToolMap, shellTool]);

  useEffect(() => {
    if (!mainConfig || !server) {
      return;
    }
    const toolMap = mainConfig[server];
    if (!toolMap) {
      return;
    }
    const toolKeys = Object.keys(toolMap);
    if (toolKeys.length === 0) {
      return;
    }

    const currentShellTool = form.getValues("shellTool") as ShellToolType;
    const nextShellTool = toolMap[currentShellTool]
      ? currentShellTool
      : (toolKeys[0] as ShellToolType);

    if (nextShellTool !== currentShellTool) {
      form.setValue("shellTool", nextShellTool);
    }

    if (nextShellTool !== ShellToolType.Custom) {
      const nextShellTypes = toolMap[nextShellTool] ?? [];
      if (nextShellTypes.length > 0) {
        const currentShellType = form.getValues("shellType");
        if (currentShellType !== nextShellTypes[0]) {
          form.setValue("shellType", nextShellTypes[0]);
        }
      }
    }

    const currentTargetJdk = form.getValues("targetJdkVersion") as string;
    const currentJdkVersion = Number.parseInt(currentTargetJdk, 10);
    const shouldRaiseJdkVersion =
      (server === "SpringWebFlux" || server === "XXLJOB" || server === "Dubbo") &&
      currentJdkVersion <= 52;
    const nextJdkVersion = shouldRaiseJdkVersion ? "52" : "50";
    if (currentTargetJdk !== nextJdkVersion) {
      form.setValue("targetJdkVersion", nextJdkVersion);
    }

    form.resetField("serverVersion");
    form.resetField("byPassJavaModule");
    form.resetField("urlPattern");
  }, [form, mainConfig, server]);

  useEffect(() => {
    if (shellTool !== ShellToolType.Custom || customShellTypes.length === 0) {
      return;
    }
    const currentShellType = form.getValues("shellType");
    if (currentShellType !== customShellTypes[0]) {
      form.setValue("shellType", customShellTypes[0]);
    }
  }, [customShellTypes, form, shellTool]);

  const handleShellToolChange = useCallback(
    (value: string) => {
      if (serverToolMap) {
        const currentShellTypes =
          value === ShellToolType.Custom ? customShellTypes : serverToolMap[value];

        // Set shellType directly instead of relying on useEffect.
        if (currentShellTypes && currentShellTypes.length > 0) {
          form.setValue("shellType", currentShellTypes[0]);
        }

        form.resetField("urlPattern");
        form.resetField("shellClassName");
        form.resetField("injectorClassName");
        clearToolParams(form, shellToolConfigs, value);
      }
      form.setValue("shellTool", value);
    },
    [customShellTypes, form, serverToolMap, shellToolConfigs],
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <ServerIcon className="h-4 w-4 text-muted-foreground" />
        <span>{t("memshell:mainConfig.title")}</span>
      </div>
      {configError ? (
        <ConfigLoadError
          className="h-100"
          error={configError}
          isRetrying={isConfigRetrying}
          onRetry={onRetryConfig}
        />
      ) : !mainConfig ? (
        <div className="flex h-100 items-center justify-center gap-4 p-4">
          <Spinner />
          <span className="text-sm text-muted-foreground">{t("loading")}</span>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            <Controller
              control={form.control}
              name="server"
              render={({ field }) => (
                <Field>
                  <FieldContent>
                    <div className="flex items-center justify-between gap-2">
                      <FieldLabel htmlFor="server">
                        <span>
                          {t("common:server")}
                          <span aria-hidden="true" className="ml-0.5 text-destructive">
                            *
                          </span>
                        </span>
                      </FieldLabel>
                      <a
                        href="https://github.com/ReaJason/MemShellParty/issues/new?template=%E8%AF%B7%E6%B1%82%E9%80%82%E9%85%8D.md"
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center text-xs text-muted-foreground underline underline-offset-4 hover:text-primary"
                      >
                        {t("memshell:tips.targetServerRequest")}
                        <ArrowUpRightIcon className="h-3.5 w-3.5" />
                      </a>
                    </div>
                    <Select
                      items={serverOptions.map((option) => ({ value: option, label: option }))}
                      onValueChange={field.onChange}
                      value={field.value}
                    >
                      <SelectTrigger id="server" aria-required="true">
                        <SelectValue data-placeholder={t("common:placeholders.select")} />
                      </SelectTrigger>
                      <SelectContent>
                        {serverOptions.map((serverOption) => (
                          <SelectItem key={serverOption} value={serverOption}>
                            {serverOption}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FieldContent>
                </Field>
              )}
            />
            <ServerVersionFormField form={form} />
          </div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            <Controller
              control={form.control}
              name="shellTool"
              render={({ field }) => (
                <Field>
                  <FieldContent>
                    <FieldLabel htmlFor="shellTool">
                      <span>
                        {t("common:shellTool")}
                        <span aria-hidden="true" className="ml-0.5 text-destructive">
                          *
                        </span>
                      </span>
                    </FieldLabel>
                    <Select
                      items={shellTools.map((tool) => ({ value: tool, label: tool }))}
                      value={field.value}
                      onValueChange={(v) => handleShellToolChange(v as string)}
                    >
                      <SelectTrigger id="shellTool" aria-required="true">
                        <SelectValue data-placeholder={t("common:placeholders.select")} />
                      </SelectTrigger>
                      <SelectContent>
                        {shellTools.map((tool) => (
                          <SelectItem key={tool} value={tool}>
                            {tool}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FieldContent>
                </Field>
              )}
            />
            <JREVersionFormField form={form} />
          </div>
          <ShellTypeFormField form={form} shellTypes={shellTypes} />
          <Separator />
          <Tabs value={shellTool} className="w-full">
            {/* 参数表单按 /api/config/shelltool/configs 下发的 @ConfigField 目录生成：
                  内置工具、SPI 插件工具同一份实现，新增工具不用再补页签 */}
            {shellToolConfigs?.map((config) =>
              config.tool === ShellToolType.Custom ? (
                <CustomTabContent key={config.tool} form={form} />
              ) : (
                <ShellToolTabContent
                  key={config.tool}
                  form={form}
                  tool={config.tool}
                  params={config.params}
                />
              ),
            )}
          </Tabs>
          <BytecodeOptions control={form.control} showProbeSwitch classForm={form} />
        </div>
      )}
      <Separator />
      <div className="flex items-center gap-2 text-sm font-semibold">
        <PackageIcon className="h-4 w-4 text-muted-foreground" />
        <span>{t("common:packerConfig.title")}</span>
      </div>
      <PackageConfigFields
        packerConfig={packerConfig}
        form={form}
        configError={packerConfigError}
        isRetrying={isPackerRetrying}
        onRetry={onRetryPacker}
      />
    </div>
  );
}
