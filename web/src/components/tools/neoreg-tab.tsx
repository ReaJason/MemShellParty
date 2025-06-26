import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FormSchema } from "@/types/schema";
import { Card, CardContent } from "../ui/card";
import { FormField, FormFieldItem, FormFieldLabel } from "../ui/form";
import { Input } from "../ui/input";
import { TabsContent } from "../ui/tabs";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export function NeoRegTabContent({
  form,
  shellTypes,
}: Readonly<{ form: UseFormReturn<FormSchema>; shellTypes: Array<string> }>) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <TabsContent value="NeoreGeorg">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="headerName"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>{t("shellToolConfig.headerName")}</FormFieldLabel>
                    <Input {...field} placeholder={t("placeholders.input")} />
                  </FormFieldItem>
                )}
              />
              <FormField
                control={form.control}
                name="headerValue"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>
                      {t("shellToolConfig.headerValue")} {t("optional")}
                    </FormFieldLabel>
                    <Input {...field} placeholder={t("placeholders.input")} />
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
