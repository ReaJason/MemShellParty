import type { ProbeShellResult, ResponseBodyConfig } from "@/types/probeshell";

import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { CopyableField } from "@/components/copyable-field";
import { FeedbackAlert } from "@/components/memshell/results/feedback-alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: ProbeShellResult }>) {
  const { t } = useTranslation();
  const isBodyContent = generateResult?.probeConfig.probeMethod === "ResponseBody";
  const isFilterContent = generateResult?.probeConfig.probeContent === "Filter";
  const isBodyCommand = isBodyContent && generateResult?.probeConfig.probeContent === "Command";
  const probeContentConfig = generateResult?.probeContentConfig as ResponseBodyConfig | undefined;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="text-md flex items-center gap-2">
            <FileTextIcon className="h-5" />
            <span>{t("common:basicInfo")}</span>
          </div>
          <FeedbackAlert />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-2">
          {!isFilterContent && isBodyContent && (
            <CopyableField
              label={t("common:paramName")}
              value={probeContentConfig?.reqParamName}
              text={probeContentConfig?.reqParamName}
            />
          )}
          {isBodyCommand && probeContentConfig?.commandTemplate && (
            <CopyableField
              label={t("common:commandTemplate")}
              value={probeContentConfig.commandTemplate}
              text={probeContentConfig.commandTemplate}
            />
          )}
          <CopyableField
            label={t("probeshell:shellClassName")}
            value={generateResult?.shellClassName}
            text={`${generateResult?.shellClassName} (${generateResult?.shellSize} bytes)`}
          />
        </div>
      </CardContent>
    </Card>
  );
}
