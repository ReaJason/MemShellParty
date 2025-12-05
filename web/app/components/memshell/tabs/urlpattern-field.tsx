import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  FormField,
  FormFieldItem,
  FormFieldLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { shouldHidden } from "@/lib/utils";
import type { MemShellFormSchema } from "@/types/schema.ts";

export function UrlPatternFormField({
  form,
}: Readonly<{ form: UseFormReturn<MemShellFormSchema> }>) {
  const { t } = useTranslation("common");
  const shellType = form.watch("shellType");
  return (
    <FormProvider {...form}>
      <FormField
        control={form.control}
        name="urlPattern"
        render={({ field }) => (
          <FormFieldItem
            className={shouldHidden(shellType) ? "hidden" : "grid"}
          >
            <FormFieldLabel>{t("urlPattern")}</FormFieldLabel>
            <Input {...field} placeholder={t("placeholders.input")} />
            <FormMessage />
          </FormFieldItem>
        )}
      />
    </FormProvider>
  );
}
