import type { MemShellResult } from "@/types/memshell";

import { DownloadIcon } from "lucide-react";
import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import CodeViewer, { RESULT_VIEWER_HEIGHT } from "@/components/code-viewer";
import { Button } from "@/components/ui/button";
import { base64ToBytes, downloadBytes, downloadContent } from "@/lib/utils";

import { AgentResult } from "./agent";
import { JarResult } from "./jar-result";

export function ResultComponent({
  packResult,
  packMethod,
  generateResult,
  onUse,
}: Readonly<{
  packResult: string | undefined;
  packMethod: string;
  generateResult?: MemShellResult;
  /** 产物出口（下载/复制产物）时触发，用于「已使用」自动标记 */
  onUse?: () => void;
}>) {
  const showCode = packMethod === "JSP";
  const isAgent = packMethod.startsWith("Agent");
  const isJar = packMethod.endsWith("Jar");
  const { t } = useTranslation();
  const shellClassName = generateResult?.shellClassName;

  const handleDownload = useCallback(() => {
    const fileName = shellClassName?.substring(shellClassName?.lastIndexOf(".") ?? 0) ?? "";
    onUse?.();
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

  if (isAgent) {
    return (
      <AgentResult
        packMethod={packMethod}
        packResult={packResult ?? ""}
        generateResult={generateResult}
        onUse={onUse}
      />
    );
  }
  if (isJar) {
    return (
      <JarResult
        packMethod={packMethod}
        packResult={packResult ?? ""}
        generateResult={generateResult}
        onUse={onUse}
      />
    );
  }

  return (
    <CodeViewer
      code={packResult ?? ""}
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
            onClick={handleDownload}
          >
            <DownloadIcon className="h-4 w-4" />
          </Button>
        ) : null
      }
      wrapLongLines={!showCode}
      showLineNumbers={showCode}
      language={showCode ? "java" : "text"}
      height={RESULT_VIEWER_HEIGHT}
      onCopy={onUse}
    />
  );
}
