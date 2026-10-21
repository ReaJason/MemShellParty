import type { MemShellResult } from "@/types/memshell";

import { DownloadIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { RESULT_VIEWER_HEIGHT } from "@/components/code-viewer";
import DecompiledCodeViewer from "@/components/decompiled-code-viewer";
import { QuickUsage } from "@/components/memshell/quick-usage";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useDecompiledSources } from "@/lib/decompile/use-decompiled-sources";
import { downloadBytes } from "@/lib/utils";

import { BasicInfo } from "./results/basic-info";
import { ResultComponent } from "./results/result-component";

export default function ShellResult({
  packResult,
  packMethod,
  generateResult,
}: Readonly<{
  packResult: string | undefined;
  packMethod: string;
  generateResult?: MemShellResult;
}>) {
  const { t } = useTranslation(["common", "memshell"]);
  const { sources, isDecompiling, error } = useDecompiledSources(generateResult);

  const shellClassName = generateResult?.shellClassName ?? "";
  const shellBytesBase64 = generateResult?.shellBytesBase64Str;
  const injectorClassName = generateResult?.injectorClassName ?? "";
  const injectorBytesBase64 = generateResult?.injectorBytesBase64Str;

  const sourcePlaceholder = isDecompiling
    ? `// ${t("common:decompiling")}`
    : error
      ? `// ${t("common:decompileFailed", { error })}`
      : "";

  return (
    <Tabs
      key={generateResult ? "generated" : "idle"}
      defaultValue={generateResult ? "generateResult" : "quickUsage"}
    >
      <TabsList variant="line" className="w-full justify-start border-b">
        <TabsTrigger value="quickUsage" className="flex-none px-3">
          {t("common:quickUsage.title")}
        </TabsTrigger>
        {generateResult && (
          <TabsTrigger value="generateResult" className="flex-none px-3">
            {t("common:generateResult")}
          </TabsTrigger>
        )}
      </TabsList>
      <TabsContent value="quickUsage" className="mt-4">
        <QuickUsage />
      </TabsContent>
      {generateResult && (
        <TabsContent value="generateResult" className="mt-4 space-y-4">
          <BasicInfo generateResult={generateResult} />

          <Tabs defaultValue="packResult">
            <TabsList>
              <TabsTrigger value="packResult">{t("common:packResult")}</TabsTrigger>
              <TabsTrigger value="shell">{t("memshell:shellClass")}</TabsTrigger>
              <TabsTrigger value="injector">{t("memshell:injectorClass")}</TabsTrigger>
            </TabsList>
            <TabsContent value="packResult" className="mt-4">
              <ResultComponent
                packResult={packResult}
                packMethod={packMethod}
                generateResult={generateResult}
              />
            </TabsContent>
            <TabsContent value="shell" className="mt-4" keepMounted>
              <DecompiledCodeViewer
                copyLabel={t("common:copy")}
                copyOptions={[
                  {
                    label: t("memshell:copySource"),
                    value: sources.shell?.source ?? "",
                    disabled: !sources.shell,
                  },
                  {
                    label: t("memshell:copyBase64"),
                    value: shellBytesBase64 ?? "",
                    disabled: !shellBytesBase64,
                  },
                ]}
                header={<div className="truncate text-xs">{shellClassName}</div>}
                button={
                  <Button
                    variant="ghost"
                    size="icon"
                    type="button"
                    className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
                    aria-label={t("common:download")}
                    title={t("common:download")}
                    onClick={() => {
                      if (!shellBytesBase64) {
                        toast.warning(t("memshell:tips.shellBytesEmpty"));
                        return;
                      }
                      downloadBytes(shellBytesBase64, shellClassName);
                    }}
                  >
                    <DownloadIcon className="h-4 w-4" />
                  </Button>
                }
                height={RESULT_VIEWER_HEIGHT}
                lines={sources.shell?.lines ?? null}
                placeholder={sourcePlaceholder}
              />
            </TabsContent>
            <TabsContent value="injector" className="mt-4" keepMounted>
              <DecompiledCodeViewer
                copyLabel={t("common:copy")}
                copyOptions={[
                  {
                    label: t("memshell:copySource"),
                    value: sources.injector?.source ?? "",
                    disabled: !sources.injector,
                  },
                  {
                    label: t("memshell:copyBase64"),
                    value: injectorBytesBase64 ?? "",
                    disabled: !injectorBytesBase64,
                  },
                ]}
                header={<div className="truncate text-xs">{injectorClassName}</div>}
                button={
                  <Button
                    variant="ghost"
                    size="icon"
                    type="button"
                    className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
                    aria-label={t("common:download")}
                    title={t("common:download")}
                    onClick={() => {
                      if (!injectorBytesBase64) {
                        toast.warning(t("memshell:tips.shellBytesEmpty"));
                        return;
                      }
                      downloadBytes(injectorBytesBase64, injectorClassName);
                    }}
                  >
                    <DownloadIcon className="h-4 w-4" />
                  </Button>
                }
                height={RESULT_VIEWER_HEIGHT}
                lines={sources.injector?.lines ?? null}
                placeholder={sourcePlaceholder}
              />
            </TabsContent>
          </Tabs>
        </TabsContent>
      )}
    </Tabs>
  );
}
