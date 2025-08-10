import { useTranslation } from "react-i18next";
import { QuickUsage } from "@/components/probe/quick-usage";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import type { ProbeGenerateResult } from "@/types/probe";
import CodeViewer from "../code-viewer";
import { MultiPackResult } from "../memshell/results/multi-packer";
import { BasicInfo } from "./basic-info";

export default function ShellResult({
  packResult,
  allPackResults,
  packMethod,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  allPackResults: Map<string, string> | undefined;
  packMethod: string;
  generateResult?: ProbeGenerateResult;
}>) {
  const { t } = useTranslation();
  if (!generateResult) {
    return <QuickUsage />;
  }
  const showCode = packMethod === "JSP";
  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-1">
        <TabsTrigger value="packResult">{t("generateResult.title1")}</TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="my-2 space-y-4">
        <BasicInfo generateResult={generateResult} />
        {
          allPackResults && <MultiPackResult allPackResults={allPackResults} packMethod={packMethod} />
        }
        {
          packResult && (
                <CodeViewer
                  code={packResult}
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
              )
        }
      </TabsContent>
    </Tabs>
  );
}
