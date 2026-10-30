import type { MemShellFormSchema } from "@/types/schema";
import type { Control, FieldValues, Path, UseFormReturn } from "react-hook-form";

import { InfoIcon } from "lucide-react";
import { Controller } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { ObfuscationScopeField } from "@/components/memshell/obfuscation-scope-field";
import { ProbeOptionsField } from "@/components/memshell/probe-options-field";
import { OptionalClassFormField } from "@/components/memshell/tabs/classname-field";
import { ObfuscationOptionsField } from "@/components/obfuscation-options-field";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface BytecodeConfigFormValues extends FieldValues {
  debug?: boolean;
  byPassJavaModule?: boolean;
  lambdaSuffix?: boolean;
  shrink?: boolean;
  staticInitialize?: boolean;
  obfuscation?: boolean;
  obfuscationOptions?: string;
}

type ToggleFieldName =
  | "debug"
  | "byPassJavaModule"
  | "lambdaSuffix"
  | "shrink"
  | "staticInitialize";

interface ToggleField {
  name: ToggleFieldName;
  labelKey: string;
  descriptionKey: string;
}

const TOGGLE_FIELDS: Array<ToggleField> = [
  { name: "debug", labelKey: "common:debug", descriptionKey: "common:debug.description" },
  {
    name: "byPassJavaModule",
    labelKey: "common:byPassJavaModule",
    descriptionKey: "common:byPassJavaModule.description",
  },
  {
    name: "lambdaSuffix",
    labelKey: "common:lambdaSuffix",
    descriptionKey: "common:lambdaSuffix.description",
  },
  { name: "shrink", labelKey: "common:shrink", descriptionKey: "common:shrink.description" },
  {
    name: "staticInitialize",
    labelKey: "common:staticInitialize",
    descriptionKey: "common:staticInitialize.description",
  },
];

/**
 * 产物相关的可选增强：随机类名 → 回显模式 → 代码混淆 → 其余字节码开关。
 * 内容型组件，既嵌入「核心配置」卡，也被探测马页的字节码卡复用。
 */
export function BytecodeOptions<T extends BytecodeConfigFormValues>({
  control,
  classForm,
}: Readonly<{
  control: Control<T>;
  /** 内存马生成页传入表单以展示随机类名和回显模式配置 */
  classForm?: UseFormReturn<MemShellFormSchema>;
}>) {
  const { t } = useTranslation(["common"]);

  const renderToggle = (field: ToggleField) => (
    <Controller
      key={field.name}
      control={control}
      name={field.name as Path<T>}
      render={({ field: controllerField }) => (
        <div className="flex items-center gap-2">
          <Checkbox
            id={field.name}
            checked={Boolean(controllerField.value)}
            onCheckedChange={controllerField.onChange}
          />
          <Label htmlFor={field.name} className="whitespace-nowrap">
            {t(field.labelKey)}
          </Label>
          <Tooltip>
            <TooltipTrigger>
              <InfoIcon className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent>
              <p>{t(field.descriptionKey)}</p>
            </TooltipContent>
          </Tooltip>
        </div>
      )}
    />
  );

  return (
    <div className="@container flex flex-col gap-3">
      {classForm && <OptionalClassFormField form={classForm} />}
      {classForm && <ProbeOptionsField form={classForm} />}
      <ObfuscationOptionsField control={control}>
        {classForm && <ObfuscationScopeField control={classForm.control} />}
      </ObfuscationOptionsField>
      <Separator />
      <div className="grid grid-cols-1 gap-4 @xs:grid-cols-2 @lg:grid-cols-3 @2xl:grid-cols-4">
        {TOGGLE_FIELDS.map(renderToggle)}
      </div>
    </div>
  );
}
