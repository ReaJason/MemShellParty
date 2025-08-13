import { PackageIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.tsx";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
} from "@/components/ui/form.tsx";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group.tsx";
import type { PackerConfig } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema.ts";

type Option = {
  name: string;
  value: string;
};

export default function PackageConfigCard({
  packerConfig,
  form,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
}>) {
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

    const mappedOptions = filteredOptions.map((name) => {
      return {
        name: t(`packageConfig.packer.${name}`),
        value: name,
      };
    });

    setOptions(mappedOptions);
    const currentValue = form.getValues("packingMethod");
    if (
      filteredOptions.length > 0 &&
      (!currentValue || !filteredOptions.includes(currentValue))
    ) {
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
        {options.length > 0 ? (
          <FormProvider {...form}>
            <FormField
              control={form.control}
              name="packingMethod"
              render={({ field }) => (
                <FormItem className="space-y-3">
                  <FormLabel>{t("packageConfig.title")}</FormLabel>
                  <FormControl>
                    <RadioGroup
                      onValueChange={field.onChange}
                      value={field.value}
                      className="grid grid-cols-2 md:grid-cols-3"
                    >
                      {options.map(({ name, value }) => (
                        <FormItem
                          key={value}
                          className="flex items-center space-x-3 space-y-0"
                        >
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
        ) : (
          <div className="flex items-center justify-center p-4 space-x-2">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <span className="text-sm text-muted-foreground">
              {t("loading")}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
