import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { CopyableField } from "@/components/copyable-field";
import { FeedbackAlert } from "@/components/memshell/results/feedback-alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ProbeShellResult, ResponseBodyConfig } from "@/types/probeshell";

export function BasicInfo({
  generateResult,
}: Readonly<{ generateResult?: ProbeShellResult }>) {
  const { t } = useTranslation();
  console.log(generateResult);
  const isBodyContent =
    generateResult?.probeConfig.probeMethod === "ResponseBody";
  const isBodyCommand =
    isBodyContent && generateResult?.probeConfig.probeContent === "Command";
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
          {isBodyContent && (
            <CopyableField
              label={t("common:paramName")}
              value={
                (generateResult?.probeContentConfig as ResponseBodyConfig)
                  .reqParamName
              }
              text={
                (generateResult?.probeContentConfig as ResponseBodyConfig)
                  .reqParamName
              }
            />
          )}
          {isBodyCommand &&
            (generateResult?.probeContentConfig as ResponseBodyConfig)
              .commandTemplate && (
              <CopyableField
                label={t("common:commandTemplate")}
                value={
                  (generateResult?.probeContentConfig as ResponseBodyConfig)
                    .commandTemplate
                }
                text={
                  (generateResult?.probeContentConfig as ResponseBodyConfig)
                    .commandTemplate
                }
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
