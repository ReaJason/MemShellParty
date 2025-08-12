import {useQuery} from "@tanstack/react-query";
import {FormProvider, type UseFormReturn} from "react-hook-form";
import {useTranslation} from "react-i18next";
import {Card, CardContent} from "@/components/ui/card";
import {FormControl, FormField, FormFieldItem, FormFieldLabel} from "@/components/ui/form";
import {Input} from "@/components/ui/input";
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from "@/components/ui/select";
import {TabsContent} from "@/components/ui/tabs";
import {env} from "@/config";
import type {MemShellFormSchema} from "@/types/schema";
import {OptionalClassFormField} from "./classname-field";
import {ShellTypeFormField} from "./shelltype-field";
import {UrlPatternFormField} from "./urlpattern-field";

export function CommandTabContent({
  form,
  shellTypes,
}: Readonly<{ form: UseFormReturn<MemShellFormSchema>; shellTypes: Array<string> }>) {
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
            <FormField
              control={form.control}
              name="commandParamName"
              render={({ field }) => (
                <FormFieldItem>
                  <FormFieldLabel>
                    {t("shellToolConfig.paramName")} {t("optional")}
                  </FormFieldLabel>
                  <FormControl>
                    <Input {...field} placeholder={t("placeholders.input")} />
                  </FormControl>
                </FormFieldItem>
              )}
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="encryptor"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>{t("shellToolConfig.encryptor")}</FormFieldLabel>
                    <Select onValueChange={field.onChange} value={field.value} defaultValue="RAW">
                      <FormControl>
                        <SelectTrigger>
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
                  </FormFieldItem>
                )}
              />
              <FormField
                control={form.control}
                name="implementationClass"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>{t("shellToolConfig.implementationClass")}</FormFieldLabel>
                    <Select onValueChange={field.onChange} value={field.value} defaultValue="RuntimeExec">
                      <FormControl>
                        <SelectTrigger>
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
