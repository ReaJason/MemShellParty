import type { BytecodeClassResponse, BytecodeResult } from "@/types/bytecode";

import { useTranslation } from "react-i18next";

import { BytecodeClassResult } from "@/components/bytecode/class-result";
import { ResultComponent } from "@/components/memshell/results/result-component";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useDecompiledSources } from "@/lib/decompile/use-decompiled-sources";

export function BytecodeResultPanel({
  input,
  result,
  isParsing,
  parseError,
  activeTab,
  onTabChange,
}: Readonly<{
  input: BytecodeClassResponse | undefined;
  result: BytecodeResult | undefined;
  isParsing: boolean;
  parseError: string | null;
  activeTab: string;
  onTabChange: (value: string) => void;
}>) {
  const { t } = useTranslation(["bytecode", "common"]);
  const original = useDecompiledSources(
    input
      ? {
          shellClassName: input.className,
          shellBytesBase64Str: input.classBytesBase64Str,
        }
      : undefined,
  );
  const transformed = useDecompiledSources(
    result
      ? {
          shellClassName: result.className,
          shellBytesBase64Str: result.classBytesBase64Str,
        }
      : undefined,
  );

  return (
    <Tabs value={activeTab} onValueChange={onTabChange} className="xl:min-h-0 xl:flex-1">
      <TabsList variant="line" className="w-full shrink-0 justify-start border-b">
        <TabsTrigger value="original" className="flex-none px-3">
          {t("originalSource")}
        </TabsTrigger>
        {result && (
          <>
            <TabsTrigger value="packResult" className="flex-none px-3">
              {t("common:packResult")}
            </TabsTrigger>
            <TabsTrigger value="transformed" className="flex-none px-3">
              {t("transformedClass")}
            </TabsTrigger>
          </>
        )}
      </TabsList>
      <TabsContent value="original" className="mt-4 xl:flex xl:min-h-0 xl:flex-col" keepMounted>
        {input ? (
          <BytecodeClassResult
            result={input}
            source={original.sources.shell}
            isDecompiling={original.isDecompiling}
            error={original.error}
          />
        ) : (
          <div className="flex min-h-64 flex-1 items-center justify-center rounded-lg border p-6 text-center text-sm text-muted-foreground">
            {isParsing
              ? t("input.parsing")
              : parseError
                ? t("input.parseFailed", { error: parseError })
                : t("input.empty")}
          </div>
        )}
      </TabsContent>
      {result && (
        <>
          <TabsContent value="packResult" className="mt-4 xl:flex xl:min-h-0 xl:flex-col xl:gap-3">
            <div className="xl:min-h-0 xl:flex-1">
              <ResultComponent packResult={result.packResult} packMethod={result.packMethod} />
            </div>
          </TabsContent>
          <TabsContent
            value="transformed"
            className="mt-4 xl:flex xl:min-h-0 xl:flex-col"
            keepMounted
          >
            <BytecodeClassResult
              result={result}
              source={transformed.sources.shell}
              isDecompiling={transformed.isDecompiling}
              error={transformed.error}
            />
          </TabsContent>
        </>
      )}
    </Tabs>
  );
}
