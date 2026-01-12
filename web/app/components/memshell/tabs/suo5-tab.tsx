import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { TabsContent } from "@/components/ui/tabs";
import type { MemShellFormSchema } from "@/types/schema";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";

export function Suo5TabContent({
  form,
  shellTypes,
  tabValue,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
  tabValue: string;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  return (
    <TabsContent value={tabValue}>
      <Card>
        <CardContent className="space-y-2 mt-4">
          <ShellTypeFormField form={form} shellTypes={shellTypes} />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <Controller
              control={form.control}
              name="headerName"
              render={({ field }) => (
                <Field className="gap-1">
                  <FieldLabel>{t("common:headerName")}</FieldLabel>
                  <Input
                    {...field}
                    placeholder={t("common:placeholders.input")}
                  />
                </Field>
              )}
            />
            <Controller
              control={form.control}
              name="headerValue"
              render={({ field }) => (
                <Field className="gap-1">
                  <FieldLabel>
                    {t("common:headerValue")} {t("common:optional")}
                  </FieldLabel>
                  <Input
                    {...field}
                    placeholder={t("common:placeholders.input")}
                  />
                </Field>
              )}
            />
          </div>
          <OptionalClassFormField form={form} />
        </CardContent>
      </Card>
    </TabsContent>
  );
}
