import type { ProbeShellResult } from "@/types/probeshell";

import { DownloadIcon } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import CodeViewer from "@/components/code-viewer";
import DecompiledCodeViewer from "@/components/decompiled-code-viewer";
import { BasicInfo } from "@/components/probeshell/basic-info";
import { QuickUsage } from "@/components/probeshell/quick-usage";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useDecompiledSources } from "@/lib/decompile/use-decompiled-sources";
import { formatRelativeTime } from "@/lib/generation-history";
import { base64ToBytes, downloadBytes, downloadContent } from "@/lib/utils";

/**
 * 探测马的连接参数比内存马少，27rem 让查看器底边贴住右栏；
 * 最坏情况 4 项参数换成两行也能放下。
 */
const PROBE_RESULT_VIEWER_HEIGHT = "clamp(256px, calc(100dvh - 27rem - 2px), 720px)";

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
  generateResult?: ProbeShellResult;
  /** 当前结果来自历史记录时，记录的生成时间 */
  restoredAt?: number | null;
  /** 产物出口（下载/复制产物本体）时触发 */
  onUse?: () => void;
  /** 「生成记录」tab 的内容 */
  historyPanel?: ReactNode;
}>) {
  const { t } = useTranslation(["common", "probeshell"]);
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

  const showCode = packMethod === "JSP";
  const shellClassName = generateResult?.shellClassName ?? "";
  const shellBytesBase64 = generateResult?.shellBytesBase64Str;

  const handleDownloadPackResult = useCallback(() => {
    onUse?.();
    const fileName = shellClassName.substring(shellClassName.lastIndexOf("."));
    if (packMethod.includes("JSP")) {
      const fileExtension = packMethod.includes("JSPX") ? ".jspx" : ".jsp";
      const content = new Blob([packResult as string], { type: "text/plain" });
      return downloadContent(content, fileName, fileExtension);
    } else if (packMethod.includes("JavaCommons") || packMethod.includes("Hessian")) {
      const content = new Blob([base64ToBytes(packResult as string)], {
        type: "application/octet-stream",
      });
      return downloadContent(content, fileName, ".data");
    } else if (packMethod === "DefaultBase64" || packMethod === "Base64") {
      return downloadBytes(packResult as string, shellClassName);
    }
  }, [packMethod, packResult, shellClassName, onUse]);

  const sourcePlaceholder = isDecompiling
    ? `// ${t("common:decompiling")}`
    : error
      ? `// ${t("common:decompileFailed", { error })}`
      : "";

  return (
    <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value)}>
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
        <TabsContent value="generateResult" className="mt-4 space-y-4">
          {restoredAt && (
            <p className="text-xs text-muted-foreground">
              {t("common:history.fromHistory", { time: formatRelativeTime(t, restoredAt) })}
            </p>
          )}
          <BasicInfo generateResult={generateResult} />

          <Tabs defaultValue="packResult">
            <TabsList>
              <TabsTrigger value="packResult">{t("common:packResult")}</TabsTrigger>
              <TabsTrigger value="shell">{t("probeshell:shellClass")}</TabsTrigger>
            </TabsList>
            <TabsContent value="packResult" className="mt-4">
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
                  button={
                    packMethod.includes("JSP") ||
                    packMethod === "DefaultBase64" ||
                    packMethod === "Base64" ||
                    packMethod.includes("JavaCommons") ||
                    packMethod.includes("Hessian") ? (
                      <Button
                        variant="ghost"
                        size="icon"
                        type="button"
                        className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
                        onClick={handleDownloadPackResult}
                      >
                        <DownloadIcon className="h-4 w-4" />
                      </Button>
                    ) : null
                  }
                  wrapLongLines={!showCode}
                  showLineNumbers={showCode}
                  language={showCode ? "java" : "text"}
                  height={PROBE_RESULT_VIEWER_HEIGHT}
                  onCopy={onUse}
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
                        toast.warning(t("probeshell:tips.shellBytesEmpty"));
                        return;
                      }
                      onUse?.();
                      downloadBytes(shellBytesBase64, shellClassName);
                    }}
                  >
                    <DownloadIcon className="h-4 w-4" />
                  </Button>
                }
                height={PROBE_RESULT_VIEWER_HEIGHT}
                lines={sources.shell?.lines ?? null}
                placeholder={sourcePlaceholder}
              />
            </TabsContent>
          </Tabs>
        </TabsContent>
      )}
    </Tabs>
  );
}
