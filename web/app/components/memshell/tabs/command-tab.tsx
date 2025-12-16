import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, InfoIcon } from "lucide-react";
import { useState } from "react";
import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TabsContent } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { env } from "@/config";
import type { MemShellFormSchema } from "@/types/schema";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export function CommandTabContent({
  form,
  shellTypes,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false);
  const { data } = useQuery<{
    encryptors: Array<string>;
    implementationClasses: Array<string>;
  }>({
    queryKey: ["commandConfigs"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/api/config/command/configs`);
      return await response.json();
    },
  });

  return (
    <TabsContent value="Command">
      <Card>
        <CardContent className="space-y-2 mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <ShellTypeFormField form={form} shellTypes={shellTypes} />
            <UrlPatternFormField form={form} />
          </div>
          <Controller
            control={form.control}
            name="commandParamName"
            render={({ field }) => (
              <Field className="gap-1">
                <div className="flex items-center gap-1">
                  <FieldLabel>
                    {t("common:paramName")} {t("common:optional")}
                  </FieldLabel>
                  <Tooltip>
                    <TooltipTrigger>
                      <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>{t("common:paramName.description")}</p>
                    </TooltipContent>
                  </Tooltip>
                </div>
                <Input
                  {...field}
                  placeholder={t("common:placeholders.input")}
                />
              </Field>
            )}
          />

          <Collapsible open={isAdvancedOpen} onOpenChange={setIsAdvancedOpen}>
            <CollapsibleTrigger className="flex items-center gap-2 w-full py-2 text-sm font-medium hover:underline">
              {isAdvancedOpen ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
              {t("common:advancedConfig")}
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-2 pt-2">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <Controller
                  control={form.control}
                  name="encryptor"
                  render={({ field }) => (
                    <Field className="gap-1">
                      <FieldLabel>{t("common:encryptor")}</FieldLabel>
                      <Select
                        onValueChange={field.onChange}
                        value={field.value}
                        defaultValue="RAW"
                      >
                        <SelectTrigger>
                          <SelectValue
                            data-placeholder={t("common:placeholders.select")}
                          />
                        </SelectTrigger>
                        <SelectContent>
                          {data?.encryptors?.map((v) => (
                            <SelectItem key={v} value={v}>
                              {v}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                  )}
                />
                <Controller
                  control={form.control}
                  name="implementationClass"
                  render={({ field }) => (
                    <Field className="gap-1">
                      <FieldLabel>{t("common:implementationClass")}</FieldLabel>
                      <Select
                        onValueChange={field.onChange}
                        value={field.value}
                        defaultValue="RuntimeExec"
                      >
                        <SelectTrigger>
                          <SelectValue
                            data-placeholder={t("common:placeholders.select")}
                          />
                        </SelectTrigger>
                        <SelectContent>
                          {data?.implementationClasses?.map((v) => (
                            <SelectItem key={v} value={v}>
                              {v}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                  )}
                />
              </div>
              <Controller
                control={form.control}
                name="commandTemplate"
                render={({ field }) => (
                  <Field className="gap-1">
                    <FieldLabel>
                      {t("common:commandTemplate")} {t("common:optional")}
                    </FieldLabel>
                    <Input
                      {...field}
                      placeholder={t("common:commandTemplate.placeholder")}
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      {t("common:commandTemplate.description")}
                    </p>
                  </Field>
                )}
              />
            </CollapsibleContent>
          </Collapsible>

          <OptionalClassFormField form={form} />
        </CardContent>
      </Card>
    </TabsContent>
  );
}
