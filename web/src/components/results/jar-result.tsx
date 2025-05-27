import { downloadBytes } from "@/lib/utils";
import { GenerateResult } from "@/types/shell";
import { useTranslation } from "react-i18next";
import { Button } from "../ui/button";

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
