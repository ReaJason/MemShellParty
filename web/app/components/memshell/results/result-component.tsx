import { useTranslation } from "react-i18next";
import CodeViewer from "@/components/code-viewer";
import type { MemShellResult } from "@/types/memshell";
import { AgentResult } from "./agent";
import { JarResult } from "./jar-result";
import { useCallback } from "react";
import { base64ToBytes, downloadBytes, downloadContent } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { DownloadIcon } from "lucide-react";

export function ResultComponent({
  packResult,
  packMethod,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  packMethod: string;
  generateResult?: MemShellResult;
}>) {
  const isAgent = packMethod.startsWith("Agent");
  const isJar = packMethod.endsWith("Jar");
  const { t } = useTranslation();
  if (isAgent) {
    return (
      <AgentResult
        packMethod={packMethod}
        packResult={packResult ?? ""}
        generateResult={generateResult}
      />
    );
  }
  if (isJar) {
    return (
      <JarResult
        packMethod={packMethod}
        packResult={packResult ?? ""}
        generateResult={generateResult}
      />
    );
  }
  const shellClassName = generateResult?.shellClassName;

  const handleDownload = useCallback(() => {
    const fileName =
      shellClassName?.substring(shellClassName?.lastIndexOf(".") ?? 0) ?? "";
    if (packMethod.includes("JSP")) {
      const fileExtension = packMethod.includes("JSPX") ? ".jspx" : ".jsp";
      const content = new Blob([packResult as string], { type: "text/plain" });
      return downloadContent(content, fileName, fileExtension);
    } else if (
      packMethod.includes("JavaCommons") ||
      packMethod.includes("Hessian")
    ) {
      const content = new Blob([base64ToBytes(packResult as string)], {
        type: "application/octet-stream",
      });
      return downloadContent(content, fileName, ".data");
    } else if (packMethod === "Base64") {
      return downloadBytes(packResult as string, shellClassName);
    }
  }, [packMethod, packResult, shellClassName]);

  return (
    <CodeViewer
      code={packResult ?? ""}
      header={
        <div className="flex items-center justify-between text-sm gap-2">
          <span>
            {t("common:packerMethod")}：{packMethod}
          </span>
          <span className="text-muted-foreground">({packResult?.length})</span>
        </div>
      }
      button={
        packMethod.includes("JSP") ||
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
      wrapLongLines={true}
      showLineNumbers={false}
      language={"text"}
      height={350}
    />
  );
}
