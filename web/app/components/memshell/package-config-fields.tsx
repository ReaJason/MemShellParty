import type { PackerConfig, PackerOption } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";

import { useMemo } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { ConfigLoadError } from "@/components/config-load-error";
import PackerSelector from "@/components/packer-selector";
import { Spinner } from "@/components/ui/spinner";

export function PackageConfigFields({
  packerConfig,
  form,
  configError,
  isRetrying,
  onRetry,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
  configError: Error | null;
  isRetrying: boolean;
  onRetry: () => void;
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

  if (configError) {
    return (
      <ConfigLoadError
        className="h-50"
        error={configError}
        isRetrying={isRetrying}
        onRetry={onRetry}
      />
    );
  }

  if (parents.length === 0) {
    return (
      <div className="flex h-50 items-center justify-center gap-4 p-4">
        <Spinner />
        <span className="text-sm text-muted-foreground">{t("loading")}</span>
      </div>
    );
  }

  return (
    <Controller
      control={form.control}
      name="packingMethod"
      render={({ field }) => (
        <PackerSelector parents={parents} value={field.value} onChange={field.onChange} />
      )}
    />
  );
}
