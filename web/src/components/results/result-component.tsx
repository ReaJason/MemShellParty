import { TFunction } from "i18next";
import CodeViewer from "@/components/code-viewer";
import { GenerateResult } from "@/types/shell";
import { AgentResult } from "./agent";
import { JarResult } from "./jar-result";
import { MultiPackResult } from "./multi-packer";

export function ResultComponent({
  packResult,
  allPackResults,
  packMethod,
  t,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  allPackResults: Map<string, string> | undefined;
  packMethod: string;
  t: TFunction;
  generateResult?: GenerateResult;
}>) {
  const showCode = packMethod === "JSP";
  const isAgent = packMethod.startsWith("Agent");
  const isJar = packMethod === "Jar";
  if (allPackResults) {
    return <MultiPackResult allPackResults={allPackResults} packMethod={packMethod} t={t} />;
  }

  if (isAgent) {
    return <AgentResult packMethod={packMethod} packResult={packResult ?? ""} generateResult={generateResult} />;
  }
  if (isJar) {
    return <JarResult packResult={packResult ?? ""} generateResult={generateResult} />;
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
