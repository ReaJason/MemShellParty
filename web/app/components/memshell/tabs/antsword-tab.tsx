import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "@/components/ui/card";
import {
  FormControl,
  FormField,
  FormFieldItem,
  FormFieldLabel,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { TabsContent } from "@/components/ui/tabs";
import type { MemShellFormSchema } from "@/types/schema";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export function AntSwordTabContent({
  form,
  shellTypes,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  return (
    <FormProvider {...form}>
      <TabsContent value="AntSword">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <FormField
              control={form.control}
              name="antSwordPass"
              render={({ field }) => (
                <FormFieldItem>
                  <FormFieldLabel>
                    {t("shellToolConfig.antSword.pass")} {t("common:optional")}
                  </FormFieldLabel>
                  <Input
                    {...field}
                    placeholder={t("common:placeholders.input")}
                  />
                </FormFieldItem>
              )}
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="headerName"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>{t("common:headerName")}</FormFieldLabel>
                    <FormControl>
                      <Input
                        {...field}
                        placeholder={t("common:placeholders.input")}
                      />
                    </FormControl>
                  </FormFieldItem>
                )}
              />
              <FormField
                control={form.control}
                name="headerValue"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>
                      {t("common:headerValue")} {t("common:optional")}
                    </FormFieldLabel>
                    <Input
                      {...field}
                      placeholder={t("common:placeholders.input")}
                    />
                  </FormFieldItem>
                )}
              />
            </div>
            <OptionalClassFormField form={form} />
          </CardContent>
        </Card>
      </TabsContent>
    </FormProvider>
  );
}
