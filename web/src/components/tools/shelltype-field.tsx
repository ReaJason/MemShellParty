import { FormControl, FormField, FormFieldItem, FormFieldLabel } from "@/components/ui/form.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import { FormSchema } from "@/types/schema.ts";

import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

export function ShellTypeFormField({
  form,
  shellTypes,
}: Readonly<{ form: UseFormReturn<FormSchema>; shellTypes: Array<string> }>) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <FormField
        control={form.control}
        name="shellType"
        render={({ field }) => (
          <FormFieldItem>
            <FormFieldLabel>{t("mainConfig.shellMountType")}</FormFieldLabel>
            <Select
              onValueChange={(e) => {
                form.resetField("urlPattern");
                field.onChange(e);
              }}
              value={field.value}
            >
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder={t("placeholders.select")} />
                </SelectTrigger>
              </FormControl>
              <SelectContent key={shellTypes?.join(",")}>
                {shellTypes?.length ? (
                  shellTypes.map((v) => (
                    <SelectItem key={v} value={v}>
                      {v}
                    </SelectItem>
                  ))
                ) : (
                  <SelectItem value=" ">{t("tips.shellToolNotSelected")}</SelectItem>
                )}
              </SelectContent>
            </Select>
          </FormFieldItem>
        )}
      />
    </FormProvider>
  );
}
