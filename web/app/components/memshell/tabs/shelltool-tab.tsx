import type { ShellToolConfigParam } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";

import { ChevronDown, ChevronRight, InfoIcon, Shuffle } from "lucide-react";
import { useRef, useState } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { TabsContent } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { isToolParamVisible } from "@/lib/tool-param-visibility";

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
  tool,
  params,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
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

  // 随机工具参数：与随机类名一致，参数全空（或仍是表单默认值）时默认开启，
  // 由后端为密码/密钥/请求头等基础参数生成随机默认值；关闭后才展示具体参数表单。
  const [randomParams, setRandomParams] = useState(() =>
    basicParams.every((param) => {
      const name = param.name as keyof MemShellFormSchema;
      const current = String(form.getValues(name) ?? "").trim();
      const initial = String(form.formState.defaultValues?.[name] ?? "").trim();
      return current === "" || current === initial;
    }),
  );
  const savedParamsRef = useRef<Record<string, string>>({});

  const handleRandomParamsChange = (checked: boolean) => {
    setRandomParams(checked);
    if (checked) {
      savedParamsRef.current = Object.fromEntries(
        basicParams.map((param) => [
          param.name,
          String(form.getValues(param.name as keyof MemShellFormSchema) ?? ""),
        ]),
      );
      for (const param of basicParams) {
        form.setValue(param.name as keyof MemShellFormSchema, "");
      }
      return;
    }
    for (const param of basicParams) {
      const value = savedParamsRef.current[param.name];
      if (value !== undefined) {
        form.setValue(param.name as keyof MemShellFormSchema, value);
      }
    }
  };

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
            </FieldLabel>
            {isEnum ? (
              <Select
                items={param.options.map((option) => ({ value: option, label: option }))}
                onValueChange={field.onChange}
                value={(field.value as string) ?? ""}
              >
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
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shuffle className="h-4 w-4" />
            <Label htmlFor={`randomToolParams-${tool}`} className="text-sm font-medium">
              {t("common:shellToolParam.random")}
            </Label>
          </div>
          <Switch
            id={`randomToolParams-${tool}`}
            checked={randomParams}
            onCheckedChange={handleRandomParamsChange}
          />
        </div>
        {!randomParams && (
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {basicParams.map(renderField)}
          </div>
        )}
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
      </div>
    </TabsContent>
  );
}

function labelKeyOf(paramName: string): string {
  const key = PARAM_LABEL_KEYS[paramName];
  return key ? `common:${key}` : paramName;
}
