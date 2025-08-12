import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { CopyableField } from "@/components/copyable-field";
import { FeedbackAlert } from "@/components/memshell/results/feedback-alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ProbeShellResult } from "@/types/probeshell";

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: ProbeShellResult }>) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="text-md flex items-center gap-2">
            <FileTextIcon className="h-5" />
            <span>{t("generateResult.basicInfo")}</span>
          </div>
          <FeedbackAlert />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-2">
          <CopyableField
            label={t("mainConfig.shellClassName")}
            value={generateResult?.shellClassName}
            text={`${generateResult?.shellClassName} (${generateResult?.shellSize} bytes)`}
          />
        </div>
      </CardContent>
    </Card>
  );
}
