import { useTranslation } from "react-i18next";
import { QuickUsage } from "@/components/probeshell/quick-usage";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs.tsx";
import type { ProbeShellResult } from "@/types/probeshell";
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
  generateResult?: ProbeShellResult;
}>) {
  const { t } = useTranslation();
  if (!generateResult) {
    return <QuickUsage />;
  }
  const showCode = packMethod === "JSP";
  const height = 550;
  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-1">
        <TabsTrigger value="packResult">
          {t("common:generateResult")}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="my-2 space-y-4">
        <BasicInfo generateResult={generateResult} />
        {allPackResults && (
          <MultiPackResult
            allPackResults={allPackResults}
            shellClassName={generateResult?.shellClassName}
            packMethod={packMethod}
            height={height}
          />
        )}
        {packResult && (
          <CodeViewer
            code={packResult}
            header={
              <div className="flex items-center justify-between text-xs gap-2">
                <span>
                  {t("common:packerMethod")}：{packMethod}
                </span>
                <span className="text-muted-foreground">
                  ({packResult?.length})
                </span>
              </div>
            }
            wrapLongLines={!showCode}
            showLineNumbers={showCode}
            language={showCode ? "java" : "text"}
            height={height}
          />
        )}
      </TabsContent>
    </Tabs>
  );
}
