import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import CodeViewer from "@/components/code-viewer";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { downloadBytes, formatBytes } from "@/lib/utils";
import type { MemShellResult } from "@/types/memshell";

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
  const isPureJar = packMethod === "Jar";
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
              {t("common:download")} {packMethod}Shell.jar (
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
      </CardContent>
    </Card>
  );
}
