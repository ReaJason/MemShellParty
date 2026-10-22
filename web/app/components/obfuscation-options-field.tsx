import type { ObfuscationOptionEntry } from "@/types/memshell";

import { useQuery } from "@tanstack/react-query";
import { BookOpenTextIcon, Ghost, RotateCcwIcon } from "lucide-react";
import { useState } from "react";
import { type Control, Controller, type FieldValues, type Path, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Field, FieldContent, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { env } from "@/config";
import { fetchJson } from "@/utils/fetch-json";

interface ObfuscationFormValues extends FieldValues {
  obfuscation?: boolean;
  obfuscationOptions?: string;
}

/**
 * 统计实际生效的自定义项，忽略空行与注释行（与 transformer 的解析规则一致）。
 */
function countCustomOptions(text?: string): number {
  if (!text) {
    return 0;
  }
  return text.split(/\r?\n/).filter((line) => {
    const trimmed = line.trim();
    return trimmed.length > 0 && !trimmed.startsWith("#") && !trimmed.startsWith("//");
  }).length;
}

const fetchObfuscationOptions = () =>
  fetchJson<Array<ObfuscationOptionEntry>>(`${env.API_URL}/api/config/obfuscation/options`);

/**
 * 参数参考弹窗：列出 OptionRegistry 注册的全部混淆参数（名称/类型/默认值/说明）。
 * 数据在弹窗首次打开时才拉取，避免给表单页加载增加一次固定请求。
 */
function ObfuscationOptionsReference() {
  const { t } = useTranslation(["common"]);
  const [open, setOpen] = useState(false);
  const optionsQuery = useQuery({
    queryKey: ["obfuscationOptions"],
    queryFn: fetchObfuscationOptions,
    enabled: open,
    staleTime: Number.POSITIVE_INFINITY,
  });
  const options = optionsQuery.data;

  const formatDefault = (value: unknown): string => {
    if (value === null || value === undefined) {
      return t("common:obfuscation.options.reference.auto");
    }
    if (Array.isArray(value)) {
      return value.length === 0
        ? t("common:obfuscation.options.reference.empty")
        : value.join(", ");
    }
    return String(value);
  };

  const formatType = (entry: ObfuscationOptionEntry): string => {
    if (entry.type === "integer" && entry.min != null && entry.max != null) {
      return `integer (${entry.min}–${entry.max})`;
    }
    return entry.type;
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          <Button type="button" variant="ghost" size="xs">
            <BookOpenTextIcon />
            {t("common:obfuscation.options.reference")}
          </Button>
        }
      />
      <DialogContent className="max-h-[85vh] grid-rows-[auto_auto_minmax(0,1fr)]">
        <DialogHeader>
          <DialogTitle>{t("common:obfuscation.options.reference.title")}</DialogTitle>
          <DialogDescription>
            {t("common:obfuscation.options.reference.description")}{" "}
            <a href="https://github.com/4ra1n/class-obf" target="_blank" rel="noreferrer">
              4ra1n/class-obf
            </a>
          </DialogDescription>
        </DialogHeader>
        <div className="overflow-y-auto rounded-md border">
          {optionsQuery.isPending && (
            <p className="p-4 text-sm text-muted-foreground">
              {t("common:obfuscation.options.reference.loading")}
            </p>
          )}
          {optionsQuery.isError && (
            <p className="p-4 text-sm text-muted-foreground">
              {t("common:obfuscation.options.reference.unavailable")}
            </p>
          )}
          {options && (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-muted">
                <tr className="text-left">
                  <th className="px-3 py-2 font-medium">
                    {t("common:obfuscation.options.reference.colName")}
                  </th>
                  <th className="px-3 py-2 font-medium whitespace-nowrap">
                    {t("common:obfuscation.options.reference.colType")}
                  </th>
                  <th className="px-3 py-2 font-medium whitespace-nowrap">
                    {t("common:obfuscation.options.reference.colDefault")}
                  </th>
                  <th className="px-3 py-2 font-medium">
                    {t("common:obfuscation.options.reference.colDescription")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {options.map((entry) => (
                  <tr key={entry.name} className="border-t align-top">
                    <td className="px-3 py-2 font-mono whitespace-nowrap">{entry.name}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-muted-foreground">
                      {formatType(entry)}
                    </td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">
                      {formatDefault(entry.defaultValue)}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">{entry.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

/**
 * 代码混淆开关与参数：与「随机类名」一致，开关开启后直接展示参数输入框；
 * 默认 STRONG 基线的说明放入 placeholder，留空即走默认值。
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
  const optionsText = useWatch({
    control,
    name: "obfuscationOptions" as Path<T>,
  }) as string | undefined;
  const customCount = countCustomOptions(optionsText);

  return (
    <div className="space-y-2">
      <Controller
        control={control}
        name={"obfuscation" as Path<T>}
        render={({ field }) => (
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Ghost className="h-4 w-4" />
              <Label htmlFor="obfuscation" className="text-sm font-medium">
                {t("common:obfuscation")}
              </Label>
            </div>
            <Switch
              id="obfuscation"
              checked={Boolean(field.value)}
              onCheckedChange={field.onChange}
            />
          </div>
        )}
      />

      {obfuscation && (
        <Controller
          control={control}
          name={"obfuscationOptions" as Path<T>}
          render={({ field }) => (
            <Field>
              <FieldContent>
                <div className="flex items-center justify-between gap-2">
                  <FieldLabel htmlFor="obfuscationOptions">
                    {t("common:obfuscation.options")}
                  </FieldLabel>
                  <div className="flex items-center gap-1">
                    <ObfuscationOptionsReference />
                    {customCount > 0 && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="xs"
                        onClick={() => field.onChange("")}
                      >
                        <RotateCcwIcon />
                        {t("common:obfuscation.options.reset")}
                      </Button>
                    )}
                  </div>
                </div>
                <Textarea
                  id="obfuscationOptions"
                  className="font-mono text-xs"
                  placeholder={t("common:obfuscation.options.placeholder")}
                  value={field.value ?? ""}
                  onChange={field.onChange}
                />
                <FieldDescription>{t("common:obfuscation.options.hint")}</FieldDescription>
              </FieldContent>
            </Field>
          )}
        />
      )}
    </div>
  );
}
