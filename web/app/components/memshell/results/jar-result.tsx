import type { MemShellResult } from "@/types/memshell";

import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { downloadBytes, formatBytes } from "@/lib/utils";

export function JarResult({
  packMethod,
  packResult,
  generateResult,
}: Readonly<{
  packMethod: string;
  packResult: string;
  generateResult?: MemShellResult;
}>) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <ScrollTextIcon className="h-4 w-4 text-muted-foreground" />
        <span>{t("common:usage")}</span>
      </div>
      <ol className="list-inside list-decimal space-y-4 text-sm">
        <li className="flex items-center justify-between">
          <span>
            {t("common:download")} {packMethod}Shell.jar ({formatBytes(atob(packResult).length)})
          </span>
          <Button
            size="sm"
            variant="outline"
            className="w-28"
            type="button"
            onClick={() =>
              downloadBytes(
                packResult,
                undefined,
                `${generateResult?.shellConfig.server}${generateResult?.shellConfig.shellTool}MemShell`,
              )
            }
          >
            {t("common:download")}
          </Button>
        </li>
        <Separator />
        <li>{t("memshell:tips.download-jar")}</li>
        <li>{t("memshell:tips.trigger-injector-class-loading")}</li>
      </ol>
    </div>
  );
}
