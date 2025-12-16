import { PackageIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldLabel } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import type { PackerConfig } from "@/types/memshell";
import type { ProbeShellFormSchema } from "@/types/schema";

type Option = {
  name: string;
  value: string;
};

export default function PackageConfigCard({
  packerConfig,
  form,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<ProbeShellFormSchema>;
}>) {
  const [options, setOptions] = useState<Array<Option>>([]);
  const { t } = useTranslation("common");

  useEffect(() => {
    const filteredOptions = (packerConfig ?? []).filter((name) => {
      return (
        !name.startsWith("Agent") &&
        !name.toLowerCase().startsWith("xxl") &&
        !name.toLowerCase().endsWith("jar")
      );
    });

    const mappedOptions = filteredOptions.map((name) => {
      return {
        name: name,
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
  }, [form, packerConfig]);

  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <PackageIcon className="h-5" />
          <span>{t("packerConfig.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {options.length > 0 ? (
          <Controller
            control={form.control}
            name="packingMethod"
            render={({ field }) => (
              <div className="space-y-3">
                <FieldLabel>{t("packerMethod")}</FieldLabel>
                <div>
                  <RadioGroup
                    onValueChange={field.onChange}
                    value={field.value}
                    className="grid grid-cols-2 md:grid-cols-3"
                  >
                    {options.map(({ name, value }) => (
                      <div key={value} className="flex items-center space-x-3">
                        <div>
                          <RadioGroupItem value={value} id={value} />
                        </div>
                        <FieldLabel className="text-xs" htmlFor={value}>
                          {name}
                        </FieldLabel>
                      </div>
                    ))}
                  </RadioGroup>
                </div>
              </div>
            )}
          />
        ) : (
          <div className="flex items-center justify-center p-4">
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
