import { FormSchema } from "@/types/schema";
import { TabsContent } from "../ui/tabs";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "../ui/card";
import { FormField, FormItem, FormLabel } from "../ui/form";
import { Input } from "../ui/input";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export function NeoRegTabContent({ form, shellTypes }: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <TabsContent value="NeoreGeorg">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="headerName"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel className="h-6 flex items-center gap-1">{t("shellToolConfig.headerName")}</FormLabel>
                    <Input {...field} placeholder={t("shellToolConfig.headerName")} className="h-8" />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="headerValue"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel className="h-6 flex items-center gap-1">{t("shellToolConfig.headerValue")}</FormLabel>
                    <Input {...field} placeholder={t("shellToolConfig.headerValue")} className="h-8" />
                  </FormItem>
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
