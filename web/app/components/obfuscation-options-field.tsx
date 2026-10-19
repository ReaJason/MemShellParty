import { InfoIcon } from "lucide-react";
import { type Control, Controller, type FieldValues, type Path, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Field, FieldContent, FieldLabel } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

interface ObfuscationFormValues extends FieldValues {
  obfuscation?: boolean;
  obfuscationOptions?: string;
}

/**
 * 混淆参数编辑框：仅在开启代码混淆时可见，每行一条 key=value，
 * 逐项覆盖默认参数（留空即按默认值启用），提交时由 transformer 解析。
 */
export function ObfuscationOptionsField<T extends ObfuscationFormValues>({
  control,
}: Readonly<{
  control: Control<T>;
}>) {
  const { t } = useTranslation(["common"]);
  const obfuscation = useWatch({
    control,
    name: "obfuscation" as Path<T>,
  });

  if (!obfuscation) {
    return null;
  }

  return (
    <Controller
      control={control}
      name={"obfuscationOptions" as Path<T>}
      render={({ field }) => (
        <Field>
          <FieldContent>
            <FieldLabel htmlFor="obfuscationOptions" className="flex items-center gap-1">
              {t("common:obfuscation.options")}
              <Tooltip>
                <TooltipTrigger>
                  <InfoIcon className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
                </TooltipTrigger>
                <TooltipContent>
                  <p>{t("common:obfuscation.options.description")}</p>
                </TooltipContent>
              </Tooltip>
            </FieldLabel>
            <Textarea
              id="obfuscationOptions"
              className="font-mono text-xs"
              placeholder="enableXOR=false"
              value={field.value ?? ""}
              onChange={field.onChange}
            />
          </FieldContent>
        </Field>
      )}
    />
  );
}
