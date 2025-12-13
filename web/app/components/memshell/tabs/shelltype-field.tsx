import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  FormControl,
  FormField,
  FormFieldItem,
  FormFieldLabel,
} from "@/components/ui/form";
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
                  <SelectValue placeholder={t("common:placeholders.select")} />
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
                  <SelectItem value=" ">
                    {t("tips.shellToolNotSelected")}
                  </SelectItem>
                )}
              </SelectContent>
            </Select>
          </FormFieldItem>
        )}
      />
    </FormProvider>
  );
}
