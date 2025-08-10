import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { downloadBytes } from "@/lib/utils";
import type { GenerateResult } from "@/types/shell";

export function JarResult({
  packResult,
  generateResult,
}: Readonly<{ packResult: string; generateResult?: GenerateResult }>) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center justify-center">
      <Button
        type="button"
        onClick={() =>
          downloadBytes(
            packResult,
            undefined,
            `${generateResult?.shellConfig.server}${generateResult?.shellConfig.shellTool}MemShell`,
          )
        }
      >
        {t("download")} Jar
      </Button>
    </div>
  );
}
