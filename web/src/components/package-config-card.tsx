import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group.tsx";
import { FormSchema } from "@/types/schema.ts";
import { PackerConfig } from "@/types/shell.ts";
import { PackageIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { FormProvider, UseFormReturn } from "react-hook-form";

export function PackageConfigCard({
  packerConfig,
  form,
}: {
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<FormSchema>;
}) {
  const [options, setOptions] = useState<Array<Array<string>>>([]);

  const shellType = form.watch("shellType");

  useEffect(() => {
    const filteredOptions = Object.entries(packerConfig ?? {}).filter(([name, _]) => {
      if (!shellType || shellType === " ") {
        return true;
      }
      if (shellType.startsWith("Agent")) {
        return name.startsWith("Agent");
      }
      return !name.startsWith("Agent");
    });
    setOptions(filteredOptions);
    if (filteredOptions.length > 0) {
      form.setValue("packingMethod", filteredOptions[0][0]);
    }
  }, [form, packerConfig, shellType]); // Add shellType to the dependency array

  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <PackageIcon className="h-5" />
          <span>打包配置</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <FormProvider {...form}>
          <FormField
            control={form.control}
            name="packingMethod"
            render={({ field }) => (
              <FormItem className="space-y-3">
                <FormLabel>打包方式</FormLabel>
                <FormControl>
                  <RadioGroup onValueChange={field.onChange} value={field.value} className="grid grid-cols-3">
                    {options.map(([name, value]) => (
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
