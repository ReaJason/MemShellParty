import type { ProbeShellResult, ResponseConfig } from "@/types/probeshell";
import { HEADER_PAYLOAD_WARNING_THRESHOLD } from "@/types/memshell";

import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { CopyableField } from "@/components/copyable-field";
import { FeedbackAlert } from "@/components/memshell/results/feedback-alert";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: ProbeShellResult }>) {
  const { t } = useTranslation(["probeshell", "common"]);
  const isResponseContent =
    generateResult?.probeConfig.probeMethod === "ResponseBody" ||
    generateResult?.probeConfig.probeMethod === "ResponseHeader";
  const isResponseHeader = generateResult?.probeConfig.probeMethod === "ResponseHeader";
  const isFilterContent = generateResult?.probeConfig.probeContent === "Filter";
  const isResponseCommand =
    isResponseContent && generateResult?.probeConfig.probeContent === "Command";
  const probeContentConfig = generateResult?.probeContentConfig as ResponseConfig | undefined;
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
          {!isFilterContent && isResponseContent && (
            <CopyableField
              label={t("common:paramName")}
              value={probeContentConfig?.reqParamName}
              text={probeContentConfig?.reqParamName}
            />
          )}
          {isResponseHeader && probeContentConfig?.respHeaderName && (
            <CopyableField
              label={t("probeshell:respHeaderName")}
              value={probeContentConfig.respHeaderName}
              text={probeContentConfig.respHeaderName}
            />
          )}
          {isResponseCommand && probeContentConfig?.commandTemplate && (
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
          {generateResult?.obfuscationInfo?.enabled &&
            generateResult.obfuscationInfo.headerPayloadTooLarge && (
              <p className="text-sm font-medium text-destructive">
                {t("common:obfuscation.headerPayloadWarning", {
                  size: generateResult.obfuscationInfo.packedPayloadSize,
                  limit: HEADER_PAYLOAD_WARNING_THRESHOLD,
                })}
              </p>
            )}
        </div>
      </CardContent>
    </Card>
  );
}
