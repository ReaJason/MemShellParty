import { PackageIcon } from "lucide-react";
import { useMemo } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldLabel, FieldSet } from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Spinner } from "@/components/ui/spinner";
import type { PackerConfig } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";

export default function PackageConfigCard({
  packerConfig,
  form,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
}>) {
  const { t } = useTranslation("common");

  const shellType = useWatch({
    control: form.control,
    name: "shellType",
  });

  const server = useWatch({
    control: form.control,
    name: "server",
  });

  const options = useMemo(() => {
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
    form.setValue("packingMethod", filteredOptions[0]);
    return filteredOptions.map((name) => ({
      name: t(name),
      value: name,
    }));
  }, [packerConfig, shellType, server, t, form]);

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
              <FieldSet>
                <FieldLabel>{t("packerMethod")}</FieldLabel>
                <RadioGroup
                  name={field.name}
                  value={field.value}
                  defaultValue={options[0].value}
                  onValueChange={field.onChange}
                  className="grid grid-cols-2 md:grid-cols-3"
                >
                  {options.map(({ name, value }) => (
                    <div key={value} className="flex items-center space-x-3">
                      <RadioGroupItem value={value} id={value} />
                      <FieldLabel className="text-xs" htmlFor={value}>
                        {name}
                      </FieldLabel>
                    </div>
                  ))}
                </RadioGroup>
              </FieldSet>
            )}
          />
        ) : (
          <div className="flex items-center justify-center p-4 gap-4 h-50">
            <Spinner />
            <span className="text-sm text-muted-foreground">
              {t("loading")}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
