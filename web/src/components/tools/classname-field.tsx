import { FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { FormSchema } from "@/types/schema.ts";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

export function OptionalClassFormField({ form }: Readonly<{ form: UseFormReturn<FormSchema> }>) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <FormField
        control={form.control}
        name="shellClassName"
        render={({ field }) => (
          <FormItem className="gap-1">
            <FormLabel className="h-6 flex items-center gap-1">
              {t("mainConfig.shellClassName")} {t("optional")}
            </FormLabel>
            <Input id="shellClassName" {...field} placeholder={t("placeholders.input")} className="h-8" />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="injectorClassName"
        render={({ field }) => (
          <FormItem className="gap-1">
            <FormLabel className="h-6 flex items-center gap-1">
              {t("mainConfig.injectorClassName")} {t("optional")}
            </FormLabel>
            <Input id="injectorClassName" {...field} placeholder={t("placeholders.input")} className="h-8" />
          </FormItem>
        )}
      />
    </FormProvider>
  );
}
