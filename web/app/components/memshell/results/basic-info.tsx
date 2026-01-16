import { FileTextIcon } from "lucide-react";
import { Fragment } from "react/jsx-runtime";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { notNeedUrlPattern } from "@/lib/utils";
import {
  type AntSwordShellToolConfig,
  type BehinderShellToolConfig,
  type CommandShellToolConfig,
  type GodzillaShellToolConfig,
  type MemShellResult,
  type NeoreGeorgShellToolConfig,
  type ProxyShellToolConfig,
  ShellToolType,
  type Suo5ShellToolConfig,
} from "@/types/memshell";
import { CopyableField } from "../../copyable-field";
import { FeedbackAlert } from "./feedback-alert";

export function BasicInfo({
  generateResult,
}: Readonly<{ generateResult?: MemShellResult }>) {
  const { t } = useTranslation(["memshell", "common"]);
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <CopyableField
            label={t("common:server")}
            text={generateResult?.shellConfig.server}
          />
          <CopyableField
            label={t("mainConfig.shellTool")}
            text={generateResult?.shellConfig.shellTool}
          />
          <CopyableField
            label={t("mainConfig.shellMountType")}
            text={generateResult?.shellConfig.shellType}
          />
          <CopyableField
            hidden={notNeedUrlPattern(generateResult?.shellConfig?.shellType)}
            label={t("common:urlPattern")}
            text={generateResult?.injectorConfig.urlPattern}
            value={generateResult?.injectorConfig.urlPattern}
          />
        </div>
        {generateResult?.shellConfig.shellTool !== ShellToolType.Custom && (
          <Separator className="my-1" />
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {generateResult?.shellConfig.shellTool === ShellToolType.Behinder && (
            <>
              <CopyableField
                label={t("shellToolConfig.behinderScriptType")}
                text="jsp"
              />
              <CopyableField
                label={t("shellToolConfig.behinderEncryptType")}
                text={t("shellToolConfig.behinderDefaultEncryptType")}
              />
              <CopyableField
                label={t("shellToolConfig.behinder.pass")}
                text={
                  (generateResult?.shellToolConfig as BehinderShellToolConfig)
                    .pass
                }
                value={
                  (generateResult?.shellToolConfig as BehinderShellToolConfig)
                    .pass
                }
              />
              <CopyableField
                label={t("shellToolConfig.behinder.header")}
                text={`${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Godzilla && (
            <>
              <CopyableField
                label={t("shellToolConfig.godzilla.pass")}
                text={
                  (generateResult?.shellToolConfig as GodzillaShellToolConfig)
                    .pass
                }
                value={
                  (generateResult?.shellToolConfig as GodzillaShellToolConfig)
                    .pass
                }
              />
              <CopyableField
                label={t("shellToolConfig.godzilla.key")}
                text={
                  (generateResult?.shellToolConfig as GodzillaShellToolConfig)
                    .key
                }
                value={
                  (generateResult?.shellToolConfig as GodzillaShellToolConfig)
                    .key
                }
              />
              <CopyableField
                label={t("shellToolConfig.godzilla.encryptor")}
                text={
                  generateResult?.shellConfig.shellType.includes("WebSocket")
                    ? "JAVA_WEBSOCKET_AES_RAW"
                    : "JAVA_AES_BASE64"
                }
              />
              <CopyableField
                label={t("shellToolConfig.godzilla.header")}
                text={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Command && (
            <Fragment>
              <CopyableField
                hidden={generateResult?.shellConfig.shellType.includes(
                  "WebSocket",
                )}
                label={t("common:paramName")}
                text={
                  (generateResult?.shellToolConfig as CommandShellToolConfig)
                    .paramName
                }
                value={
                  (generateResult?.shellToolConfig as CommandShellToolConfig)
                    .paramName
                }
              />
              <CopyableField
                hidden={
                  !(
                    generateResult?.shellConfig.shellType ===
                      "BypassNginxWebSocket" ||
                    generateResult?.shellConfig.shellType ===
                      "BypassNginxJakartaWebSocket"
                  )
                }
                label={t("shellToolConfig.httpHeader")}
                text={`${(generateResult?.shellToolConfig as CommandShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as CommandShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as CommandShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as CommandShellToolConfig).headerValue}`}
              />
            </Fragment>
          )}
          {(generateResult?.shellConfig.shellTool === ShellToolType.Suo5 ||
            generateResult?.shellConfig.shellTool === ShellToolType.Suo5v2) && (
            <CopyableField
              label={t("shellToolConfig.suo5Header")}
              text={`${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerValue}`}
            />
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Proxy && (
            <CopyableField
              label={t("shellToolConfig.httpHeader")}
              text={`${(generateResult?.shellToolConfig as ProxyShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as ProxyShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as ProxyShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as ProxyShellToolConfig).headerValue}`}
            />
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.AntSword && (
            <>
              <CopyableField
                label={t("shellToolConfig.antSword.pass")}
                text={
                  (generateResult?.shellToolConfig as AntSwordShellToolConfig)
                    .pass
                }
                value={
                  (generateResult?.shellToolConfig as AntSwordShellToolConfig)
                    .pass
                }
              />
              <CopyableField
                label={t("shellToolConfig.httpHeader")}
                text={`${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as AntSwordShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool ===
            ShellToolType.NeoreGeorg && (
            <>
              <CopyableField
                label={t("shellToolConfig.neoreGeorgKey")}
                text="key"
                value="key"
              />
              <CopyableField
                label={t("shellToolConfig.neoreGeorgHeader")}
                text={`${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
                value={`${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
              />
            </>
          )}
        </div>
        <Separator className="my-1" />
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
