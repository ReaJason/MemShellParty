import { Card, CardContent } from "@/components/ui/card";
import { TabsContent } from "@/components/ui/tabs";
import { FormSchema } from "@/types/schema";
import { t } from "i18next";
import { useState } from "react";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { FormControl, FormField, FormItem, FormLabel } from "../ui/form";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { RadioGroup, RadioGroupItem } from "../ui/radio-group";
import { Textarea } from "../ui/textarea";
import { OptionalClassFormField } from "./classname-field";
import { ShellTypeFormField } from "./shelltype-field";
import { UrlPatternFormField } from "./urlpattern-field";

export default function CustomTabContent({
  form,
  shellTypes,
}: Readonly<{ form: UseFormReturn<FormSchema>; shellTypes: Array<string> }>) {
  const [isFile, setIsFile] = useState(false);

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
                <FormItem className="gap-1">
                  <FormLabel className="h-6 flex items-center gap-1">{t("shellToolConfig.base64String")}</FormLabel>
                  <RadioGroup
                    value={isFile ? "file" : "base64"}
                    onValueChange={(value) => {
                      field.onChange("");
                      setIsFile(value === "file");
                    }}
                    className="flex items-center space-x-2"
                  >
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="base64" id="option-one" />
                      <Label htmlFor="option-one">Base64</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="file" id="option-two" />
                      <Label htmlFor="option-two">File</Label>
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
                              const base64String = (event.target?.result as string)?.split(",")[1] || "";
                              field.onChange(base64String);
                            };
                            reader.readAsDataURL(file);
                          }
                        }}
                        accept=".class"
                        placeholder={t("placeholders.input")}
                        type="file"
                      />
                    ) : (
                      <Textarea {...field} placeholder={t("placeholders.input")} className="h-24" />
                    )}
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
