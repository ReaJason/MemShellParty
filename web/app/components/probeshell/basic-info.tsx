import type { ProbeShellResult, ResponseConfig } from "@/types/probeshell";

import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { CopyableField } from "@/components/copyable-field";
import { FeedbackAlert } from "@/components/memshell/results/feedback-alert";
import { Separator } from "@/components/ui/separator";
import { usesRequestParam } from "@/lib/probe-config";

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: ProbeShellResult }>) {
  const { t } = useTranslation(["probeshell", "common"]);
  const isResponseContent =
    generateResult?.probeConfig.probeMethod === "ResponseBody" ||
    generateResult?.probeConfig.probeMethod === "ResponseHeader";
  const isResponseHeader = generateResult?.probeConfig.probeMethod === "ResponseHeader";
  const isResponseCommand =
    isResponseContent && generateResult?.probeConfig.probeContent === "Command";
  const probeContentConfig = generateResult?.probeContentConfig as ResponseConfig | undefined;
  const showReqParamName =
    isResponseContent &&
    !!probeContentConfig?.reqParamName &&
    usesRequestParam(generateResult?.probeConfig.probeContent, probeContentConfig?.server);
  const showRespHeaderName = isResponseHeader && !!probeContentConfig?.respHeaderName;
  const showCommandTemplate = isResponseCommand && !!probeContentConfig?.commandTemplate;
  const showParams = showReqParamName || showRespHeaderName || showCommandTemplate;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <FileTextIcon className="h-4 w-4 text-muted-foreground" />
          <span>{t("probeshell:connectionParams")}</span>
        </div>
        <FeedbackAlert />
      </div>
      <div className="@container flex flex-col gap-2">
        {showParams && (
          <div className="grid grid-cols-1 gap-2 @md:grid-cols-2 @2xl:grid-cols-3 @4xl:grid-cols-4">
            {showReqParamName && (
              <CopyableField
                label={t("common:paramName")}
                value={probeContentConfig?.reqParamName}
                text={probeContentConfig?.reqParamName}
              />
            )}
            {showRespHeaderName && (
              <CopyableField
                label={t("probeshell:respHeaderName")}
                value={probeContentConfig?.respHeaderName}
                text={probeContentConfig?.respHeaderName}
              />
            )}
            {showCommandTemplate && (
              <CopyableField
                label={t("common:commandTemplate")}
                value={probeContentConfig?.commandTemplate}
                text={probeContentConfig?.commandTemplate}
              />
            )}
          </div>
        )}
        {showParams && <Separator className="my-1" />}
        <div className="grid grid-cols-1 gap-2 @md:grid-cols-2 @2xl:grid-cols-3 @4xl:grid-cols-4">
          <CopyableField
            className="col-span-full"
            label={t("probeshell:shellClassName")}
            value={generateResult?.shellClassName}
            text={`${generateResult?.shellClassName} (${generateResult?.shellSize} bytes)`}
          />
        </div>
      </div>
    </div>
  );
}
