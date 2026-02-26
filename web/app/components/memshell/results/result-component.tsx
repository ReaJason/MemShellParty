import { useTranslation } from "react-i18next";
import CodeViewer from "@/components/code-viewer";
import type { MemShellResult } from "@/types/memshell";
import { AgentResult } from "./agent";
import { JarResult } from "./jar-result";

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
      wrapLongLines={true}
      showLineNumbers={false}
      language={"text"}
      height={350}
    />
  );
}
