import { FormSchema } from "@/types/schema";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "../ui/card";
import { FormControl, FormField, FormItem, FormLabel } from "../ui/form";
import { Input } from "../ui/input";
import { TabsContent } from "../ui/tabs";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export function CommandTabContent({
  form,
  shellTypes,
}: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  const { t } = useTranslation();
  return (
    <FormProvider {...form}>
      <TabsContent value="Command">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <FormField
              control={form.control}
              name="commandParamName"
              render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel className="h-6 flex items-center gap-1">{t("shellToolConfig.paramName")}</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder={t("shellToolConfig.paramName")} className="h-8" />
                  </FormControl>
                </FormItem>
              )}
            />
            <OptionalClassFormField form={form} />
          </CardContent>
        </Card>
      </TabsContent>
    </FormProvider>
  );
}
