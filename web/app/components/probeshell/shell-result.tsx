import type { ProbeShellResult } from "@/types/probeshell";

import { DownloadIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import DecompiledCodeViewer from "@/components/decompiled-code-viewer";
import { QuickUsage } from "@/components/probeshell/quick-usage";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useDecompiledSources } from "@/lib/decompile/use-decompiled-sources";
import { downloadBytes } from "@/lib/utils";

import CodeViewer from "../code-viewer";
import { BasicInfo } from "./basic-info";

export default function ShellResult({
  packResult,
  packMethod,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  packMethod: string;
  generateResult?: ProbeShellResult;
}>) {
  const { t } = useTranslation(["common", "probeshell"]);
  const { sources, isDecompiling, error } = useDecompiledSources(generateResult);

  if (!generateResult) {
    return <QuickUsage />;
  }

  const showCode = packMethod === "JSP";
  const height = 600;
  const decompiledSourceHeight = 800;
  const shellClassName = generateResult.shellClassName;
  const shellBytesBase64 = generateResult.shellBytesBase64Str;
  const sourcePlaceholder = isDecompiling
    ? `// ${t("common:decompiling")}`
    : error
      ? `// ${t("common:decompileFailed", { error })}`
      : "";

  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="packResult">{t("common:generateResult")}</TabsTrigger>
        <TabsTrigger value="shell">{t("probeshell:shellClass")}</TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="space-y-2">
        <BasicInfo generateResult={generateResult} />
        {packResult && (
          <CodeViewer
            code={packResult}
            header={
              <div className="flex items-center justify-between gap-2 text-xs">
                <span>
                  {t("common:packerMethod")}：{packMethod}
                </span>
                <span className="text-muted-foreground">({packResult?.length})</span>
              </div>
            }
            wrapLongLines={!showCode}
            showLineNumbers={showCode}
            language={showCode ? "java" : "text"}
            height={height}
          />
        )}
      </TabsContent>
      <TabsContent value="shell" className="mt-4" keepMounted>
        <DecompiledCodeViewer
          copyLabel={t("common:copy")}
          copyOptions={[
            {
              label: t("probeshell:copySource"),
              value: sources.shell?.source ?? "",
              disabled: !sources.shell,
            },
            {
              label: t("probeshell:copyBase64"),
              value: shellBytesBase64 ?? "",
              disabled: !shellBytesBase64,
            },
          ]}
          header={<div className="truncate text-xs">{shellClassName}</div>}
          button={
            <Button
              variant="ghost"
              size="icon"
              type="button"
              className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
              aria-label={t("common:download")}
              title={t("common:download")}
              onClick={() => {
                if (!shellBytesBase64) {
                  toast.warning(t("probeshell:tips.shellBytesEmpty"));
                  return;
                }
                downloadBytes(shellBytesBase64, shellClassName);
              }}
            >
              <DownloadIcon className="h-4 w-4" />
            </Button>
          }
          height={decompiledSourceHeight}
          lines={sources.shell?.lines ?? null}
          placeholder={sourcePlaceholder}
        />
      </TabsContent>
    </Tabs>
  );
}
