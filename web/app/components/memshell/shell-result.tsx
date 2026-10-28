import type { MemShellResult } from "@/types/memshell";

import { DownloadIcon } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { RESULT_VIEWER_HEIGHT } from "@/components/code-viewer";
import DecompiledCodeViewer from "@/components/decompiled-code-viewer";
import { QuickUsage } from "@/components/memshell/quick-usage";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useDecompiledSources } from "@/lib/decompile/use-decompiled-sources";
import { formatRelativeTime } from "@/lib/generation-history";
import { downloadBytes } from "@/lib/utils";

import { BasicInfo } from "./results/basic-info";
import { ResultComponent } from "./results/result-component";

export default function ShellResult({
  packResult,
  packMethod,
  generateResult,
  restoredAt,
  onUse,
  historyPanel,
}: Readonly<{
  packResult: string | undefined;
  packMethod: string;
  generateResult?: MemShellResult;
  /** 当前结果来自历史记录时，记录的生成时间 */
  restoredAt?: number | null;
  /** 产物出口（下载/复制产物本体）时触发 */
  onUse?: () => void;
  /** 「生成记录」tab 的内容 */
  historyPanel?: ReactNode;
}>) {
  const { t } = useTranslation(["common", "memshell"]);
  const { sources, isDecompiling, error } = useDecompiledSources(generateResult);

  const [activeTab, setActiveTab] = useState<string>(
    generateResult ? "generateResult" : "quickUsage",
  );
  // 新结果（生成或从历史记录选中）到达时切回「生成结果」tab
  const lastResultRef = useRef(generateResult);
  useEffect(() => {
    if (generateResult && generateResult !== lastResultRef.current) {
      setActiveTab("generateResult");
    }
    lastResultRef.current = generateResult;
  }, [generateResult]);

  const shellClassName = generateResult?.shellClassName ?? "";
  const shellBytesBase64 = generateResult?.shellBytesBase64Str;
  const helperClassName = generateResult?.helperClassName ?? "";
  const helperBytesBase64 = generateResult?.helperBytesBase64Str;
  const injectorClassName = generateResult?.injectorClassName ?? "";
  const injectorBytesBase64 = generateResult?.injectorBytesBase64Str;

  const sourcePlaceholder = isDecompiling
    ? `// ${t("common:decompiling")}`
    : error
      ? `// ${t("common:decompileFailed", { error })}`
      : "";

  return (
    <Tabs
      value={activeTab}
      onValueChange={(value) => setActiveTab(value)}
      className="xl:min-h-0 xl:flex-1"
    >
      <TabsList variant="line" className="w-full justify-start border-b">
        <TabsTrigger value="quickUsage" className="flex-none px-3">
          {t("common:quickUsage.title")}
        </TabsTrigger>
        <TabsTrigger value="generationHistory" className="flex-none px-3">
          {t("common:history.title")}
        </TabsTrigger>
        {generateResult && (
          <TabsTrigger value="generateResult" className="flex-none px-3">
            {t("common:generateResult")}
          </TabsTrigger>
        )}
      </TabsList>
      <TabsContent value="quickUsage" className="mt-4">
        <QuickUsage />
      </TabsContent>
      <TabsContent value="generationHistory" className="mt-4">
        {historyPanel}
      </TabsContent>
      {generateResult && (
        <TabsContent
          value="generateResult"
          className="mt-4 space-y-4 xl:flex xl:min-h-0 xl:flex-col"
        >
          {restoredAt && (
            <p className="text-xs text-muted-foreground">
              {t("common:history.fromHistory", { time: formatRelativeTime(t, restoredAt) })}
            </p>
          )}
          <BasicInfo generateResult={generateResult} />

          <Tabs defaultValue="packResult" className="xl:min-h-0 xl:flex-1">
            <TabsList className="shrink-0">
              <TabsTrigger value="packResult">{t("common:packResult")}</TabsTrigger>
              <TabsTrigger value="shell">{t("memshell:shellClass")}</TabsTrigger>
              {helperBytesBase64 && (
                <TabsTrigger value="helper">{t("memshell:helperClass")}</TabsTrigger>
              )}
              <TabsTrigger value="injector">{t("memshell:injectorClass")}</TabsTrigger>
            </TabsList>
            <TabsContent value="packResult" className="mt-4 xl:min-h-0">
              <ResultComponent
                packResult={packResult}
                packMethod={packMethod}
                generateResult={generateResult}
                onUse={onUse}
              />
            </TabsContent>
            <TabsContent value="shell" className="mt-4 xl:min-h-0" keepMounted>
              <DecompiledCodeViewer
                copyLabel={t("common:copy")}
                copyOptions={[
                  {
                    label: t("memshell:copySource"),
                    value: sources.shell?.source ?? "",
                    disabled: !sources.shell,
                  },
                  {
                    label: t("memshell:copyBase64"),
                    value: shellBytesBase64 ?? "",
                    disabled: !shellBytesBase64,
                    onCopy: onUse,
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
                        toast.warning(t("memshell:tips.shellBytesEmpty"));
                        return;
                      }
                      onUse?.();
                      downloadBytes(shellBytesBase64, shellClassName);
                    }}
                  >
                    <DownloadIcon className="h-4 w-4" />
                  </Button>
                }
                height={RESULT_VIEWER_HEIGHT}
                fillHeight
                lines={sources.shell?.lines ?? null}
                placeholder={sourcePlaceholder}
              />
            </TabsContent>
            {helperBytesBase64 && (
              <TabsContent value="helper" className="mt-4 xl:min-h-0" keepMounted>
                <DecompiledCodeViewer
                  copyLabel={t("common:copy")}
                  copyOptions={[
                    {
                      label: t("memshell:copySource"),
                      value: sources.helper?.source ?? "",
                      disabled: !sources.helper,
                    },
                    {
                      label: t("memshell:copyBase64"),
                      value: helperBytesBase64,
                      onCopy: onUse,
                    },
                  ]}
                  header={<div className="truncate text-xs">{helperClassName}</div>}
                  button={
                    <Button
                      variant="ghost"
                      size="icon"
                      type="button"
                      className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
                      aria-label={t("common:download")}
                      title={t("common:download")}
                      onClick={() => {
                        onUse?.();
                        downloadBytes(helperBytesBase64, helperClassName);
                      }}
                    >
                      <DownloadIcon className="h-4 w-4" />
                    </Button>
                  }
                  height={RESULT_VIEWER_HEIGHT}
                  fillHeight
                  lines={sources.helper?.lines ?? null}
                  placeholder={sourcePlaceholder}
                />
              </TabsContent>
            )}
            <TabsContent value="injector" className="mt-4 xl:min-h-0" keepMounted>
              <DecompiledCodeViewer
                copyLabel={t("common:copy")}
                copyOptions={[
                  {
                    label: t("memshell:copySource"),
                    value: sources.injector?.source ?? "",
                    disabled: !sources.injector,
                  },
                  {
                    label: t("memshell:copyBase64"),
                    value: injectorBytesBase64 ?? "",
                    disabled: !injectorBytesBase64,
                    onCopy: onUse,
                  },
                ]}
                header={<div className="truncate text-xs">{injectorClassName}</div>}
                button={
                  <Button
                    variant="ghost"
                    size="icon"
                    type="button"
                    className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
                    aria-label={t("common:download")}
                    title={t("common:download")}
                    onClick={() => {
                      if (!injectorBytesBase64) {
                        toast.warning(t("memshell:tips.shellBytesEmpty"));
                        return;
                      }
                      onUse?.();
                      downloadBytes(injectorBytesBase64, injectorClassName);
                    }}
                  >
                    <DownloadIcon className="h-4 w-4" />
                  </Button>
                }
                height={RESULT_VIEWER_HEIGHT}
                fillHeight
                lines={sources.injector?.lines ?? null}
                placeholder={sourcePlaceholder}
              />
            </TabsContent>
          </Tabs>
        </TabsContent>
      )}
    </Tabs>
  );
}
