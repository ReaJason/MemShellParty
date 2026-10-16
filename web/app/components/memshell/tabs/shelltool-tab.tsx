import type { ShellToolConfigParam } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";

import { ChevronDown, ChevronRight, InfoIcon } from "lucide-react";
import { useState } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Card, CardContent } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TabsContent } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { isToolParamVisible } from "@/lib/tool-param-visibility";

import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";

/**
 * 工具参数的中文/英文标签，与结果区（results/basic-info.tsx）用词一致；没登记的参数直接显示参数名，
 * 所以 SPI 插件工具的参数也不用改这里。
 */
const PARAM_LABEL_KEYS: Record<string, string> = {
  pass: "shellToolParam.pass",
  key: "shellToolParam.key",
  paramName: "paramName",
  template: "commandTemplate",
  encryptor: "encryptor",
  implementationClass: "implementationClass",
  headerName: "headerName",
  headerValue: "headerValue",
};

/**
 * 工具参数卡片：按 `/api/config/shelltool/configs` 下发的 `@ConfigField` 目录动态生成表单 ——
 * String → 输入框，枚举 → 下拉框，字段声明顺序就是表单顺序，BASIC 直接铺开、ADVANCED 收进「高级配置」。
 * 内置工具与 SPI 插件工具共用这一份实现；只有 Custom（Base64 ⇄ .class）另有专用页签。
 */
export function ShellToolTabContent({
  form,
  shellTypes,
  tool,
  params,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
  tool: string;
  params: Array<ShellToolConfigParam>;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const server = useWatch({ control: form.control, name: "server" });
  const shellType = useWatch({ control: form.control, name: "shellType" });

  const visibleParams = params.filter((param) =>
    isToolParamVisible(tool, param.name, server, shellType),
  );
  const basicParams = visibleParams.filter((param) => param.group !== "ADVANCED");
  const advancedParams = visibleParams.filter((param) => param.group === "ADVANCED");

  const renderField = (param: ShellToolConfigParam) => {
    const isEnum = param.type === "enum";
    const label = t(labelKeyOf(param.name));
    // 参数说明可有可无（如 paramName.description），没有就不显示问号
    const description = t(`${labelKeyOf(param.name)}.description`, { defaultValue: "" });
    return (
      <Controller
        key={param.name}
        control={form.control}
        name={param.name as keyof MemShellFormSchema}
        render={({ field }) => (
          <Field className="gap-1">
            <FieldLabel>
              <span className="flex items-center gap-1">
                {label}
                {description && (
                  <Tooltip>
                    <TooltipTrigger>
                      <InfoIcon className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>{description}</p>
                    </TooltipContent>
                  </Tooltip>
                )}
              </span>
              {!isEnum && t("common:optional")}
            </FieldLabel>
            {isEnum ? (
              <Select onValueChange={field.onChange} value={(field.value as string) ?? ""}>
                <SelectTrigger>
                  <SelectValue data-placeholder={t("common:placeholders.select")} />
                </SelectTrigger>
                <SelectContent>
                  {param.options.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Input
                {...field}
                value={(field.value as string) ?? ""}
                placeholder={t(`${labelKeyOf(param.name)}.placeholder`, {
                  defaultValue: t("common:placeholders.input"),
                })}
              />
            )}
          </Field>
        )}
      />
    );
  };

  return (
    <TabsContent value={tool}>
      <Card>
        <CardContent className="mt-4 space-y-2">
          <ShellTypeFormField form={form} shellTypes={shellTypes} />
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {basicParams.map(renderField)}
          </div>
          {advancedParams.length > 0 && (
            <Collapsible open={isAdvancedOpen} onOpenChange={setIsAdvancedOpen}>
              <CollapsibleTrigger className="flex w-full items-center gap-2 py-2 text-sm font-medium hover:underline">
                {isAdvancedOpen ? (
                  <ChevronDown className="h-4 w-4" />
                ) : (
                  <ChevronRight className="h-4 w-4" />
                )}
                {t("common:advancedConfig")}
              </CollapsibleTrigger>
              <CollapsibleContent className="pt-2">
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  {advancedParams.map(renderField)}
                </div>
              </CollapsibleContent>
            </Collapsible>
          )}
          <OptionalClassFormField form={form} />
        </CardContent>
      </Card>
    </TabsContent>
  );
}

function labelKeyOf(paramName: string): string {
  const key = PARAM_LABEL_KEYS[paramName];
  return key ? `common:${key}` : paramName;
}
