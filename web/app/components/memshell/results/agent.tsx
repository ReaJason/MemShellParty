import type { MemShellResult } from "@/types/memshell";

import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { downloadBytes, formatBytes } from "@/lib/utils";

export function AgentResult({
  packMethod,
  packResult,
  generateResult,
  onUse,
}: Readonly<{
  packMethod: string;
  packResult: string;
  generateResult?: MemShellResult;
  onUse?: () => void;
}>) {
  const { t } = useTranslation(["common"]);
  const isPureAgent = packMethod === "AgentJar";
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <ScrollTextIcon className="h-4 w-4 text-muted-foreground" />
        <span>{t("common:usage")}</span>
      </div>
      <ol className="list-inside list-decimal space-y-4 text-sm">
        <li className="flex items-center justify-between">
          <span>
            {t("common:download")} MemShellAgent.jar ({formatBytes(atob(packResult).length)})
          </span>
          <Button
            size="sm"
            variant="outline"
            className="w-28"
            type="button"
            onClick={() => {
              onUse?.();
              downloadBytes(
                packResult,
                undefined,
                `${generateResult?.shellConfig.server}${generateResult?.shellConfig.shellTool}MemShellAgent`,
              );
            }}
          >
            {t("common:download")}
          </Button>
        </li>
        {isPureAgent && (
          <li className="flex items-center justify-between">
            <span>{t("memshell:tips.download-jattach")}</span>
            <Button
              size="sm"
              variant="outline"
              className="w-28"
              type="button"
              onClick={() => window.open("https://github.com/jattach/jattach/releases")}
            >
              {t("common:download")}
            </Button>
          </li>
        )}
        <Separator />
        <li>
          {isPureAgent
            ? t("memshell:tips.agent-move-to-target")
            : t("memshell:tips.agent-move-to-target1")}
        </li>
        <li>{t("memshell:tips.get-pid")}</li>
        <li>
          {isPureAgent ? t("memshell:tips.execute-command") : t("memshell:tips.execute-command1")}
        </li>
        {!isPureAgent && <li>{t("memshell:tips.execute-command-all")}</li>}
        <li>{t("memshell:tips.try-to-use-shell")}</li>
      </ol>
    </div>
  );
}
