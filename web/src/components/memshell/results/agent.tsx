import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { downloadBytes, formatBytes } from "@/lib/utils";
import type { MemShellResult } from "@/types/memshell";

export function AgentResult({
  packMethod,
  packResult,
  generateResult,
}: Readonly<{
  packMethod: string;
  packResult: string;
  generateResult?: MemShellResult;
}>) {
  const { t } = useTranslation();
  const isPureAgent = packMethod === "AgentJar";
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-md flex items-center gap-2">
          <ScrollTextIcon className="h-5" />
          <span>{t("common:usage")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal list-inside space-y-4 text-sm">
          <li className="flex items-center justify-between">
            <span>
              {t("common:download")} MemShellAgent.jar (
              {formatBytes(atob(packResult).length)})
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
                  `${generateResult?.shellConfig.server}${generateResult?.shellConfig.shellTool}MemShellAgent`,
                )
              }
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
                onClick={() =>
                  window.open("https://github.com/jattach/jattach/releases")
                }
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
            {isPureAgent
              ? t("memshell:tips.execute-command")
              : t("memshell:tips.execute-command1")}
          </li>
          <li>{t("memshell:tips.try-to-use-shell")}</li>
        </ol>
      </CardContent>
    </Card>
  );
}
