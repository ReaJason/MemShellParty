import { CodeViewer } from "@/components/code-viewer.tsx";
import { QuickUsage } from "@/components/quick-usage.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { downloadBytes } from "@/lib/utils.ts";
import { GenerateResult } from "@/types/shell.ts";
import { TriangleAlertIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { BasicInfo } from "./results/basic-info";
import { ResultComponent } from "./results/result-component";

export function ShellResult({
  packResult,
  allPackResults,
  packMethod,
  generateResult,
}: {
  packResult: string | undefined;
  allPackResults: Map<string, string> | undefined;
  packMethod: string;
  generateResult?: GenerateResult;
}) {
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
      <TabsContent value="packResult" className="my-4 space-y-4">
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
        <Alert>
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>{t("tips.decompileTip")}</AlertDescription>
        </Alert>
        <div className="gap-4 my-2 flex items-center justify-end">
          <Button
            size="sm"
            variant="outline"
            className="w-28"
            type="button"
            onClick={() => {
              if (!generateResult?.shellBytesBase64Str) {
                toast.warning(t("tips.shellBytesEmpty"));
                return;
              }
              downloadBytes(generateResult?.shellBytesBase64Str, generateResult?.shellClassName);
            }}
          >
            {t("download")} Class
          </Button>
        </div>
        <CodeViewer
          showLineNumbers={false}
          header={<div className="text-xs">{generateResult?.shellClassName}</div>}
          wrapLongLines={true}
          height={600}
          code={generateResult?.shellBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
      <TabsContent value="injector" className="mt-4">
        <Alert>
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>{t("tips.decompileTip")}</AlertDescription>
        </Alert>
        <div className="gap-4 my-2 flex items-center justify-end">
          <Button
            size="sm"
            className="w-28"
            variant="outline"
            type="button"
            onClick={() => {
              if (!generateResult?.injectorBytesBase64Str) {
                toast.warning(t("tips.shellBytesEmpty"));
                return;
              }
              downloadBytes(generateResult?.injectorBytesBase64Str, generateResult?.injectorClassName);
            }}
          >
            {t("download")} Class
          </Button>
        </div>
        <CodeViewer
          showLineNumbers={false}
          wrapLongLines={true}
          header={<div className="text-xs">{generateResult?.injectorClassName}</div>}
          height={600}
          code={generateResult?.injectorBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
    </Tabs>
  );
}
