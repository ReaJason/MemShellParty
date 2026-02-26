import { useTranslation } from "react-i18next";
import { QuickUsage } from "@/components/probeshell/quick-usage";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ProbeShellResult } from "@/types/probeshell";
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
  const { t } = useTranslation();
  if (!generateResult) {
    return <QuickUsage />;
  }
  const height = 600;
  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-1">
        <TabsTrigger value="packResult">
          {t("common:generateResult")}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="space-y-2">
        <BasicInfo generateResult={generateResult} />
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
            wrapLongLines={true}
            showLineNumbers={false}
            language={"text"}
            height={height}
          />
        )}
      </TabsContent>
    </Tabs>
  );
}
