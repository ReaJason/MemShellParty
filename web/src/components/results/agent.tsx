import { downloadBytes } from "@/lib/utils";
import { GenerateResult } from "@/types/shell";
import { Separator } from "@radix-ui/react-dropdown-menu";
import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export function AgentResult({ packResult, generateResult }: { packResult: string; generateResult?: GenerateResult }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-md flex items-center gap-2">
          <ScrollTextIcon className="h-5" />
          <span>{t("generateResult.usage")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal list-inside space-y-4 text-sm">
          <li className="flex items-center justify-between">
            <span>{t("download")} MemShellAgent.jar</span>
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
              {t("download")} Jar
            </Button>
          </li>
          <li className="flex items-center justify-between">
            <span>{t("tips.download-jattach")}</span>
            <Button
              size="sm"
              variant="outline"
              className="w-28"
              type="button"
              onClick={() => window.open("https://github.com/jattach/jattach/releases")}
            >
              {t("download")} Jattach
            </Button>
          </li>
          <Separator />
          <li>{t("tips.move-to-container")}</li>
          <li>{t("tips.get-pid")}</li>
          <li>{t("tips.execute-command")}</li>
          <li>{t("tips.try-to-use-shell")}</li>
        </ol>
      </CardContent>
    </Card>
  );
}
