import type { PackerConfig, PackerOption } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";

import { PackageIcon } from "lucide-react";
import { useMemo } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import PackerSelector from "@/components/packer-selector";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";

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

  const parents = useMemo<PackerOption[]>(() => {
    return (packerConfig ?? []).filter(({ name }) => {
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
  }, [packerConfig, shellType, server]);

  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <PackageIcon className="h-5" />
          <span>{t("packerConfig.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {parents.length > 0 ? (
          <Controller
            control={form.control}
            name="packingMethod"
            render={({ field }) => (
              <PackerSelector parents={parents} value={field.value} onChange={field.onChange} />
            )}
          />
        ) : (
          <div className="flex h-50 items-center justify-center gap-4 p-4">
            <Spinner />
            <span className="text-sm text-muted-foreground">{t("loading")}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
