import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FormField, FormFieldItem, FormFieldLabel, FormMessage } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { shouldHidden } from "@/lib/utils";
import { FormSchema } from "@/types/schema.ts";

export function UrlPatternFormField({ form }: Readonly<{ form: UseFormReturn<FormSchema> }>) {
  const { t } = useTranslation();
  const shellType = form.watch("shellType");
  return (
    <FormProvider {...form}>
      <FormField
        control={form.control}
        name="urlPattern"
        render={({ field }) => (
          <FormFieldItem className={shouldHidden(shellType) ? "hidden" : "grid"}>
            <FormFieldLabel>{t("mainConfig.urlPattern")}</FormFieldLabel>
            <Input {...field} placeholder={t("placeholders.input")} />
            <FormMessage />
          </FormFieldItem>
        )}
      />
    </FormProvider>
  );
}
