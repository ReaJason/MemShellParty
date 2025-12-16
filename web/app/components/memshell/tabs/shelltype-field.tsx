import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Field, FieldLabel } from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { MemShellFormSchema } from "@/types/schema";

export function ShellTypeFormField({
  form,
  shellTypes,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  return (
    <Controller
      control={form.control}
      name="shellType"
      render={({ field }) => (
        <Field className="gap-1">
          <FieldLabel>{t("mainConfig.shellMountType")}</FieldLabel>
          <Select
            onValueChange={(e) => {
              form.resetField("urlPattern");
              field.onChange(e);
            }}
            value={field.value}
          >
            <SelectTrigger>
              <SelectValue data-placeholder={t("common:placeholders.select")} />
            </SelectTrigger>
            <SelectContent key={shellTypes?.join(",")}>
              {shellTypes?.length ? (
                shellTypes.map((v) => (
                  <SelectItem key={v} value={v}>
                    {v}
                  </SelectItem>
                ))
              ) : (
                <SelectItem value=" ">
                  {t("tips.shellToolNotSelected")}
                </SelectItem>
              )}
            </SelectContent>
          </Select>
        </Field>
      )}
    />
  );
}
