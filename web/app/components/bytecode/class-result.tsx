import type { DecompiledClass } from "@/lib/decompile/decompile.worker";
import type { BytecodeClassResponse } from "@/types/bytecode";

import { DownloadIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { RESULT_VIEWER_HEIGHT } from "@/components/code-viewer";
import DecompiledCodeViewer from "@/components/decompiled-code-viewer";
import { Button } from "@/components/ui/button";
import { downloadBytes, formatBytes } from "@/lib/utils";

export function BytecodeClassResult({
  result,
  source,
  isDecompiling,
  error,
}: Readonly<{
  result: BytecodeClassResponse;
  source: DecompiledClass | null;
  isDecompiling: boolean;
  error: string | null;
}>) {
  const { t } = useTranslation(["bytecode", "common"]);
  const placeholder = isDecompiling
    ? `// ${t("common:decompiling")}`
    : error
      ? `// ${t("common:decompileFailed", { error })}`
      : "";

  return (
    <DecompiledCodeViewer
      copyLabel={t("common:copy")}
      copyOptions={[
        {
          label: t("copySource"),
          value: source?.source ?? "",
          disabled: !source,
        },
        {
          label: t("copyBase64"),
          value: result.classBytesBase64Str,
        },
      ]}
      header={
        <div className="flex min-w-0 items-center gap-2 text-xs">
          <span className="truncate" title={result.className}>
            {result.className}
          </span>
          <span className="shrink-0 text-muted-foreground">({formatBytes(result.size)})</span>
        </div>
      }
      button={
        <Button
          variant="ghost"
          size="icon"
          type="button"
          className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
          aria-label={t("common:download")}
          title={t("common:download")}
          onClick={() => downloadBytes(result.classBytesBase64Str, result.className)}
        >
          <DownloadIcon className="h-4 w-4" />
        </Button>
      }
      height={RESULT_VIEWER_HEIGHT}
      fillHeight
      lines={source?.lines ?? null}
      placeholder={placeholder}
    />
  );
}
