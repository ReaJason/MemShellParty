import type { MemShellFormSchema } from "@/types/schema";

import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn, notNeedUrlPattern } from "@/lib/utils";

export function ShellTypeFormField({
  form,
  shellTypes,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  const shellType = useWatch({ control: form.control, name: "shellType" });
  const needUrlPattern = !notNeedUrlPattern(shellType);
  const shellTypeItems = shellTypes.length
    ? shellTypes.map((value) => ({ value, label: value }))
    : [{ value: " ", label: t("tips.shellToolNotSelected") }];
  return (
    <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
      <Controller
        control={form.control}
        name="shellType"
        render={({ field }) => (
          <Field className="gap-1">
            <FieldLabel>
              <span>
                {t("mainConfig.shellMountType")}
                <span aria-hidden="true" className="ml-0.5 text-destructive">
                  *
                </span>
              </span>
            </FieldLabel>
            <Select
              items={shellTypeItems}
              onValueChange={(e) => {
                form.resetField("urlPattern");
                field.onChange(e);
              }}
              value={field.value}
            >
              <SelectTrigger aria-required="true">
                <SelectValue data-placeholder={t("common:placeholders.select")} />
              </SelectTrigger>
              <SelectContent key={shellTypes?.join(",")}>
                {shellTypeItems.map(({ value, label }) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        )}
      />
      <Controller
        control={form.control}
        name="urlPattern"
        render={({ field, fieldState }) => (
          <Field
            className={cn("gap-1", needUrlPattern ? "grid" : "hidden")}
            data-invalid={fieldState.invalid}
          >
            <FieldLabel>{t("common:urlPattern")}</FieldLabel>
            <Input {...field} placeholder={t("common:placeholders.input")} />
            {fieldState.error && <FieldError errors={[fieldState.error]} />}
          </Field>
        )}
      />
    </div>
  );
}
