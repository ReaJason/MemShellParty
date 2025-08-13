import { useTranslation } from "react-i18next";
import CodeViewer from "@/components/code-viewer";
import type { MemShellResult } from "@/types/memshell";
import { AgentResult } from "./agent";
import { JarResult } from "./jar-result";
import { MultiPackResult } from "./multi-packer";

export function ResultComponent({
  packResult,
  allPackResults,
  packMethod,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  allPackResults: Map<string, string> | undefined;
  packMethod: string;
  generateResult?: MemShellResult;
}>) {
  const showCode = packMethod === "JSP";
  const isAgent = packMethod.startsWith("Agent");
  const isJar = packMethod === "Jar";
  const { t } = useTranslation();
  if (allPackResults) {
    return (
      <MultiPackResult
        allPackResults={allPackResults}
        packMethod={packMethod}
      />
    );
  }

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
        packResult={packResult ?? ""}
        generateResult={generateResult}
      />
    );
  }
  if (!isAgent && !isJar) {
    return (
      <CodeViewer
        code={packResult ?? ""}
        header={
          <div className="flex items-center justify-between text-xs gap-2">
            <span>
              {t("packageConfig.title")}：{packMethod}
            </span>
            <span className="text-muted-foreground">({packResult?.length})</span>
          </div>
        }
        wrapLongLines={!showCode}
        showLineNumbers={showCode}
        language={showCode ? "java" : "text"}
        height={350}
      />
    );
  }
  return null;
}
