import { DownloadIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { QuickUsage } from "@/components/quick-usage.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { downloadBytes } from "@/lib/utils.ts";
import { GenerateResult } from "@/types/shell.ts";
import CodeViewer from "./code-viewer";
import { BasicInfo } from "./results/basic-info";
import { ResultComponent } from "./results/result-component";

export default function ShellResult({
  packResult,
  allPackResults,
  packMethod,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  allPackResults: Map<string, string> | undefined;
  packMethod: string;
  generateResult?: GenerateResult;
}>) {
  const { t } = useTranslation();
  if (!generateResult) {
    return <QuickUsage />;
  }
  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-3">
        <TabsTrigger value="packResult">{t("generateResult.title1")}</TabsTrigger>
        <TabsTrigger value="shell">{t("generateResult.title2")}</TabsTrigger>
        <TabsTrigger value="injector">{t("generateResult.title3")}</TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="my-2 space-y-4">
        <BasicInfo generateResult={generateResult} />
        <ResultComponent
          packResult={packResult}
          allPackResults={allPackResults}
          packMethod={packMethod}
          t={t}
          generateResult={generateResult}
        />
      </TabsContent>
      <TabsContent value="shell" className="mt-4">
        <CodeViewer
          showLineNumbers={false}
          header={<div className="text-xs truncate">{generateResult?.shellClassName}</div>}
          button={
            <Button
              variant="ghost"
              size="icon"
              type="button"
              className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
              onClick={() => {
                if (!generateResult?.shellBytesBase64Str) {
                  toast.warning(t("tips.shellBytesEmpty"));
                  return;
                }
                downloadBytes(generateResult?.shellBytesBase64Str, generateResult?.shellClassName);
              }}
            >
              <DownloadIcon className="h-4 w-4" />
            </Button>
          }
          wrapLongLines={true}
          height={600}
          code={generateResult?.shellBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
      <TabsContent value="injector" className="mt-4">
        <CodeViewer
          showLineNumbers={false}
          wrapLongLines={true}
          header={<div className="text-xs">{generateResult?.injectorClassName}</div>}
          button={
            <Button
              variant="ghost"
              size="icon"
              type="button"
              className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
              onClick={() => {
                if (!generateResult?.injectorBytesBase64Str) {
                  toast.warning(t("tips.shellBytesEmpty"));
                  return;
                }
                downloadBytes(generateResult?.injectorBytesBase64Str, generateResult?.injectorClassName);
              }}
            >
              <DownloadIcon className="h-4 w-4" />
            </Button>
          }
          height={600}
          code={generateResult?.injectorBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
    </Tabs>
  );
}
