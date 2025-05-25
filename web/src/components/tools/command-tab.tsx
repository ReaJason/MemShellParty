import { env } from "@/config";
import { FormSchema } from "@/types/schema";
import { useQuery } from "@tanstack/react-query";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "../ui/card";
import { FormControl, FormField, FormItem, FormLabel } from "../ui/form";
import { Input } from "../ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { TabsContent } from "../ui/tabs";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export function CommandTabContent({
  form,
  shellTypes,
}: Readonly<{ form: UseFormReturn<FormSchema>; shellTypes: Array<string> }>) {
  const { t } = useTranslation();
  const { data } = useQuery<{ encryptors: Array<string>; implementationClasses: Array<string> }>({
    queryKey: ["commandConfigs"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/config/command/configs`);
      return await response.json();
    },
  });

  return (
    <FormProvider {...form}>
      <TabsContent value="Command">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="commandParamName"
                render={({ field }) => (
                  <FormItem className="gap-1">
                    <FormLabel className="h-6 flex items-center gap-1">
                      {t("shellToolConfig.paramName")} {t("optional")}
                    </FormLabel>
                    <FormControl>
                      <Input {...field} placeholder={t("placeholders.input")} className="h-8" />
                    </FormControl>
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="encryptor"
                render={({ field }) => (
                  <FormItem className="gap-1">
                    <FormLabel className="h-6 flex items-center">{t("shellToolConfig.encryptor")}</FormLabel>
                    <Select onValueChange={field.onChange} value={field.value} defaultValue="RAW">
                      <FormControl>
                        <SelectTrigger className="h-8">
                          <SelectValue placeholder={t("placeholders.select")} />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {data?.encryptors?.map((v) => (
                          <SelectItem key={v} value={v}>
                            {v}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="implementationClass"
                render={({ field }) => (
                  <FormItem className="gap-1">
                    <FormLabel className="h-6 flex items-center">{t("shellToolConfig.implementationClass")}</FormLabel>
                    <Select onValueChange={field.onChange} value={field.value} defaultValue="RuntimeExec">
                      <FormControl>
                        <SelectTrigger className="h-8">
                          <SelectValue placeholder={t("placeholders.select")} />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {data?.implementationClasses?.map((v) => (
                          <SelectItem key={v} value={v}>
                            {v}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
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
