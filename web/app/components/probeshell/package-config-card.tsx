import type { PackerConfig, PackerOption } from "@/types/memshell";
import type { ProbeShellFormSchema } from "@/types/schema";

import { PackageIcon } from "lucide-react";
import { useMemo } from "react";
import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

import PackerSelector from "@/components/packer-selector";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function PackageConfigCard({
  packerConfig,
  form,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<ProbeShellFormSchema>;
}>) {
  const { t } = useTranslation("common");

  const parents = useMemo<PackerOption[]>(() => {
    return (packerConfig ?? []).filter(({ name }) => {
      return (
        !name.startsWith("Agent") &&
        !name.toLowerCase().startsWith("xxl") &&
        !name.toLowerCase().endsWith("jar")
      );
    });
  }, [packerConfig]);

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
          <div className="flex items-center justify-center p-4">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <span className="text-sm text-muted-foreground">{t("loading")}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
