import { UrlPatternTip } from "@/components/tips/url-pattern-tip.tsx";
import { FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { FormSchema } from "@/types/schema.ts";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

export function UrlPatternFormField({ form }: Readonly<{ form: UseFormReturn<FormSchema> }>) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <FormField
        control={form.control}
        name="urlPattern"
        render={({ field }) => (
          <FormItem className="space-y-1">
            <FormLabel className="h-6 flex items-center gap-1">
              {t("mainConfig.urlPattern")} <UrlPatternTip />
            </FormLabel>
            <Input {...field} placeholder={t("placeholders.input")} className="h-8" />
          </FormItem>
        )}
      />
    </FormProvider>
  );
}
