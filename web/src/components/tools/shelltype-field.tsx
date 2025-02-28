import { FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import { FormSchema } from "@/types/schema.ts";

import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

export function ShellTypeFormField({
  form,
  shellTypes,
}: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <FormField
        control={form.control}
        name="shellType"
        render={({ field }) => (
          <FormItem className="space-y-1">
            <FormLabel className="h-6 flex items-center">{t("mainConfig.shellMountType")}</FormLabel>
            <Select onValueChange={field.onChange} value={field.value}>
              <FormControl>
                <SelectTrigger className="h-8">
                  <SelectValue placeholder={t("placeholders.select")} />
                </SelectTrigger>
              </FormControl>
              <SelectContent key={shellTypes.join(",")}>
                {shellTypes.length ? (
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
          </FormItem>
        )}
      />
    </FormProvider>
  );
}
