import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Fragment } from "react/jsx-runtime";

import { Separator } from "@/components/ui/separator";
import { notNeedUrlPattern } from "@/lib/utils";
import {
  type AntSwordShellToolConfig,
  type BehinderShellToolConfig,
  type CommandShellToolConfig,
  type GodzillaShellToolConfig,
  HEADER_PAYLOAD_WARNING_THRESHOLD,
  type MemShellResult,
  type NeoreGeorgShellToolConfig,
  ShellToolType,
  type Suo5ShellToolConfig,
} from "@/types/memshell";

import { CopyableField } from "../../copyable-field";
import { FeedbackAlert } from "./feedback-alert";

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: MemShellResult }>) {
  const { t } = useTranslation(["memshell", "common"]);
  const isDubbo = generateResult?.shellConfig.server === "Dubbo";
  const shellToolConfig = generateResult?.shellToolConfig;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <FileTextIcon className="h-4 w-4 text-muted-foreground" />
          <span>{t("memshell:connectionParams")}</span>
        </div>
        <FeedbackAlert />
      </div>
      <div className="@container flex flex-col gap-2">
        {!notNeedUrlPattern(generateResult?.shellConfig?.shellType) && (
          <>
            <div className="grid grid-cols-1 gap-2 @md:grid-cols-2 @2xl:grid-cols-3 @4xl:grid-cols-4">
              <CopyableField
                label={t("common:urlPattern")}
                text={generateResult?.injectorConfig.urlPattern}
                value={generateResult?.injectorConfig.urlPattern}
              />
            </div>
            {generateResult?.shellConfig.shellTool !== ShellToolType.Custom && !isDubbo && (
              <Separator className="my-1" />
            )}
          </>
        )}
        <div className="grid grid-cols-1 gap-2 @md:grid-cols-2 @2xl:grid-cols-3 @4xl:grid-cols-4">
          {generateResult?.shellConfig.shellTool === ShellToolType.Behinder && (
            <>
              <CopyableField label={t("shellToolConfig.behinderScriptType")} text="jsp" />
              <CopyableField
                label={t("shellToolConfig.behinderEncryptType")}
                text={t("shellToolConfig.behinderDefaultEncryptType")}
              />
              <CopyableField
                label={t("shellToolConfig.behinder.pass")}
                text={(shellToolConfig as BehinderShellToolConfig).pass}
                value={(shellToolConfig as BehinderShellToolConfig).pass}
              />
              <CopyableField
                className="col-span-2"
                label={t("shellToolConfig.behinder.header")}
                text={`${(shellToolConfig as BehinderShellToolConfig).headerName}: ${(shellToolConfig as BehinderShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as BehinderShellToolConfig).headerName}: ${(shellToolConfig as BehinderShellToolConfig).headerValue}`}
              />
            </>
          )}
          {(generateResult?.shellConfig.shellTool === ShellToolType.Godzilla ||
            generateResult?.shellConfig.shellTool === ShellToolType.GodzillaSession) && (
            <>
              <CopyableField
                label={t("shellToolConfig.godzilla.pass")}
                text={(shellToolConfig as GodzillaShellToolConfig).pass}
                value={(shellToolConfig as GodzillaShellToolConfig).pass}
              />
              <CopyableField
                label={t("shellToolConfig.godzilla.key")}
                text={(shellToolConfig as GodzillaShellToolConfig).key}
                value={(shellToolConfig as GodzillaShellToolConfig).key}
              />
              <CopyableField
                label={t("shellToolConfig.godzilla.encryptor")}
                text={
                  generateResult?.shellConfig.shellType.includes("WebSocket")
                    ? "JAVA_WEBSOCKET_AES_RAW"
                    : generateResult?.shellConfig.shellType.includes("Dubbo")
                      ? "DUBBO_XOR_BASE64"
                      : "JAVA_AES_BASE64"
                }
              />
              <CopyableField
                className="col-span-2"
                label={t("shellToolConfig.godzilla.header")}
                text={`${(shellToolConfig as GodzillaShellToolConfig).headerName}: ${(shellToolConfig as GodzillaShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as GodzillaShellToolConfig).headerName}: ${(shellToolConfig as GodzillaShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Command && !isDubbo && (
            <Fragment>
              <CopyableField
                hidden={generateResult?.shellConfig.shellType.includes("WebSocket")}
                label={t("common:paramName")}
                text={(shellToolConfig as CommandShellToolConfig).paramName}
                value={(shellToolConfig as CommandShellToolConfig).paramName}
              />
            </Fragment>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Suo5 && (
            <CopyableField
              className="col-span-2"
              label={t("shellToolConfig.suo5Header")}
              text={`${(shellToolConfig as Suo5ShellToolConfig).headerName}: ${(shellToolConfig as Suo5ShellToolConfig).headerValue}`}
              value={`${(shellToolConfig as Suo5ShellToolConfig).headerName}: ${(shellToolConfig as Suo5ShellToolConfig).headerValue}`}
            />
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.AntSword && (
            <>
              <CopyableField
                label={t("shellToolConfig.antSword.pass")}
                text={(shellToolConfig as AntSwordShellToolConfig).pass}
                value={(shellToolConfig as AntSwordShellToolConfig).pass}
              />
              <CopyableField
                className="col-span-2"
                label={t("shellToolConfig.httpHeader")}
                text={`${(shellToolConfig as AntSwordShellToolConfig).headerName}: ${(shellToolConfig as AntSwordShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as AntSwordShellToolConfig).headerName}: ${(shellToolConfig as AntSwordShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.NeoreGeorg && (
            <>
              <CopyableField label={t("shellToolConfig.neoreGeorgKey")} text="key" value="key" />
              <CopyableField
                className="col-span-2"
                label={t("shellToolConfig.neoreGeorgHeader")}
                text={`${(shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
              />
            </>
          )}
        </div>
        <Separator className="my-1" />
        <div className="grid grid-cols-1 gap-2 @md:grid-cols-2 @2xl:grid-cols-3 @4xl:grid-cols-4">
          <CopyableField
            className="col-span-full"
            label={t("mainConfig.injectorClassName")}
            value={generateResult?.injectorClassName}
            text={`${generateResult?.injectorClassName} (${generateResult?.injectorSize} bytes)`}
          />
          <CopyableField
            className="col-span-full"
            label={t("mainConfig.shellClassName")}
            value={generateResult?.shellClassName}
            text={`${generateResult?.shellClassName} (${generateResult?.shellSize} bytes)`}
          />
        </div>
        {generateResult?.obfuscationInfo?.enabled &&
          generateResult.obfuscationInfo.headerPayloadTooLarge && (
            <>
              <Separator className="my-1" />
              <p className="text-sm font-medium text-destructive">
                {t("common:obfuscation.headerPayloadWarning", {
                  size: generateResult.obfuscationInfo.packedPayloadSize,
                  limit: HEADER_PAYLOAD_WARNING_THRESHOLD,
                })}
              </p>
            </>
          )}
      </div>
    </div>
  );
}
