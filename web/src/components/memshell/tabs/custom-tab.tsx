import { useState } from "react";
import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "@/components/ui/card";
import {
  FormControl,
  FormField,
  FormFieldItem,
  FormFieldLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { TabsContent } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import type { MemShellFormSchema } from "@/types/schema";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export default function CustomTabContent({
  form,
  shellTypes,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
}>) {
  const [isFile, setIsFile] = useState(false);
  const { t } = useTranslation(["memshell", "common"]);
  return (
    <FormProvider {...form}>
      <TabsContent value="Custom">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <FormField
              control={form.control}
              name="shellClassBase64"
              render={({ field }) => (
                <FormFieldItem>
                  <FormFieldLabel>{t("shellClass")}</FormFieldLabel>
                  <RadioGroup
                    value={isFile ? "file" : "base64"}
                    onValueChange={(value) => {
                      field.onChange("");
                      setIsFile(value === "file");
                    }}
                    className="flex items-center space-x-2"
                  >
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="base64" id="optionOne" />
                      <Label htmlFor="optionOne">Base64</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="file" id="optionTwo" />
                      <Label htmlFor="optionTwo">File</Label>
                    </div>
                  </RadioGroup>
                  <FormControl className="mt-2">
                    {isFile ? (
                      <Input
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) {
                            const reader = new FileReader();
                            reader.onload = (event) => {
                              const base64String =
                                (event.target?.result as string)?.split(
                                  ",",
                                )[1] || "";
                              field.onChange(base64String);
                            };
                            reader.readAsDataURL(file);
                          }
                        }}
                        accept=".class"
                        placeholder={t("common:placeholders.input")}
                        type="file"
                      />
                    ) : (
                      <Textarea
                        {...field}
                        placeholder={t("common:placeholders.input")}
                        className="h-24"
                      />
                    )}
                  </FormControl>
                  <FormMessage />
                </FormFieldItem>
              )}
            />
            <OptionalClassFormField form={form} />
          </CardContent>
        </Card>
      </TabsContent>
    </FormProvider>
  );
}
