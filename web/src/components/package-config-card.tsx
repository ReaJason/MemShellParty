import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group.tsx";
import { FormSchema } from "@/types/schema.ts";
import { PackerConfig } from "@/types/shell.ts";
import { PackageIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

type Option = {
  name: string;
  value: string;
};

export function PackageConfigCard({
  packerConfig,
  form,
}: {
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<FormSchema>;
}) {
  const [options, setOptions] = useState<Array<Option>>([]);

  const shellType = form.watch("shellType");
  const server = form.watch("server");
  const { t } = useTranslation();

  useEffect(() => {
    const filteredOptions = (packerConfig ?? []).filter((name) => {
      if (!shellType || shellType === " ") {
        return true;
      }
      if (shellType.startsWith("Agent")) {
        return name.startsWith("Agent");
      }
      if (server.startsWith("XXL")) {
        return !name.startsWith("Agent");
      }
      return !name.startsWith("Agent") && !name.toLowerCase().startsWith("xxl");
    });
    setOptions(
      filteredOptions.map((name) => {
        return {
          name: t(`packageConfig.packer.${name}`),
          value: name,
        };
      }),
    );
    if (filteredOptions.length > 0) {
      form.setValue("packingMethod", filteredOptions[0]);
    }
  }, [form, packerConfig, server, shellType, t]);

  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <PackageIcon className="h-5" />
          <span>{t("configs.package-config")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <FormProvider {...form}>
          <FormField
            control={form.control}
            name="packingMethod"
            render={({ field }) => (
              <FormItem className="space-y-3">
                <FormLabel className="h-6 flex items-center gap-1">{t("packageConfig.title")}</FormLabel>
                <FormControl>
                  <RadioGroup
                    onValueChange={field.onChange}
                    value={field.value}
                    className="grid grid-cols-2 md:grid-cols-3"
                  >
                    {options.map(({ name, value }) => (
                      <FormItem key={value} className="flex items-center space-x-3 space-y-0">
                        <FormControl>
                          <RadioGroupItem value={value} id={value} />
                        </FormControl>
                        <FormLabel className="text-xs" htmlFor={value}>
                          {name}
                        </FormLabel>
                      </FormItem>
                    ))}
                  </RadioGroup>
                </FormControl>
              </FormItem>
            )}
          />
        </FormProvider>
      </CardContent>
    </Card>
  );
}
