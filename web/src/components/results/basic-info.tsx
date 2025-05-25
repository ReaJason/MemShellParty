import { shouldHidden } from "@/lib/utils";
import {
  AntSwordShellToolConfig,
  BehinderShellToolConfig,
  CommandShellToolConfig,
  GenerateResult,
  GodzillaShellToolConfig,
  NeoreGeorgShellToolConfig,
  ShellToolType,
  Suo5ShellToolConfig,
} from "@/types/shell";
import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { CopyableField } from "../copyable-field";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Separator } from "../ui/separator";
import { FeedbackAlert } from "./feedback-alert";

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: GenerateResult }>) {
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <CopyableField label={t("mainConfig.server")} text={generateResult?.shellConfig.server} />
          <CopyableField label={t("mainConfig.shellTool")} text={generateResult?.shellConfig.shellTool} />
          <CopyableField label={t("mainConfig.shellMountType")} text={generateResult?.shellConfig.shellType} />
          {!shouldHidden(generateResult?.shellConfig?.shellType) && (
            <CopyableField
              label={t("mainConfig.urlPattern")}
              text={generateResult?.injectorConfig.urlPattern}
              value={generateResult?.injectorConfig.urlPattern}
            />
          )}
        </div>
        {generateResult?.shellConfig.shellTool !== ShellToolType.Custom && <Separator className="my-2" />}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {generateResult?.shellConfig.shellTool === ShellToolType.Behinder && (
            <>
              <CopyableField label={t("shellToolConfig.behinderScriptType")} text="jsp" />
              <CopyableField
                label={t("shellToolConfig.behinderEncryptType")}
                text={t("shellToolConfig.behinderDefaultEncryptType")}
              />
              <CopyableField
                label={t("shellToolConfig.behinderPass")}
                text={(generateResult?.shellToolConfig as BehinderShellToolConfig).pass}
                value={(generateResult?.shellToolConfig as BehinderShellToolConfig).pass}
              />
              <CopyableField
                label={t("shellToolConfig.customHeader")}
                text={`${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Godzilla && (
            <>
              <CopyableField
                label={t("shellToolConfig.pass")}
                text={(generateResult?.shellToolConfig as GodzillaShellToolConfig).pass}
                value={(generateResult?.shellToolConfig as GodzillaShellToolConfig).pass}
              />
              <CopyableField
                label={t("shellToolConfig.key")}
                text={(generateResult?.shellToolConfig as GodzillaShellToolConfig).key}
                value={(generateResult?.shellToolConfig as GodzillaShellToolConfig).key}
              />
              <CopyableField label={t("shellToolConfig.godzillaEncryptor")} text="JAVA_AES_BASE64" />
              <CopyableField
                label={t("shellToolConfig.godzillaHeader")}
                text={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Command && (
            <CopyableField
              label={t("shellToolConfig.paramName")}
              text={(generateResult?.shellToolConfig as CommandShellToolConfig).paramName}
              value={(generateResult?.shellToolConfig as CommandShellToolConfig).paramName}
            />
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Suo5 && (
            <CopyableField
              label={t("shellToolConfig.suo5Header")}
              text={`${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerValue}`}
            />
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.AntSword && (
            <>
              <CopyableField
                label={t("shellToolConfig.antSwordPass")}
                text={(generateResult?.shellToolConfig as AntSwordShellToolConfig).pass}
                value={(generateResult?.shellToolConfig as AntSwordShellToolConfig).pass}
              />
              <CopyableField
                label={t("shellToolConfig.httpHeader")}
                text={`${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.NeoreGeorg && (
            <>
              <CopyableField label={t("shellToolConfig.neoreGeorgKey")} text="key" value="key" />
              <CopyableField
                label={t("shellToolConfig.neoreGeorgHeader")}
                text={`${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
              />
            </>
          )}
        </div>
        <Separator className="my-2" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <CopyableField
            label={t("mainConfig.injectorClassName")}
            value={generateResult?.injectorClassName}
            text={`${generateResult?.injectorClassName} (${generateResult?.injectorSize} bytes)`}
          />
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
