import { FileTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Fragment } from "react/jsx-runtime";

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

export function BasicInfo({ generateResult }: Readonly<{ generateResult?: MemShellResult }>) {
  const { t } = useTranslation(["memshell", "common"]);
  const isDubbo = generateResult?.shellConfig.server === "Dubbo";
  const shellToolConfig = generateResult?.shellToolConfig;
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
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          <CopyableField label={t("common:server")} text={generateResult?.shellConfig.server} />
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
        {generateResult?.shellConfig.shellTool !== ShellToolType.Custom && !isDubbo && (
          <Separator className="my-1" />
        )}
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
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
                label={t("shellToolConfig.behinder.header")}
                text={`${(shellToolConfig as BehinderShellToolConfig).headerName}: ${(shellToolConfig as BehinderShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as BehinderShellToolConfig).headerName}: ${(shellToolConfig as BehinderShellToolConfig).headerValue}`}
              />
            </>
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Godzilla && (
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
              <CopyableField
                hidden={
                  !(
                    generateResult?.shellConfig.shellType === "BypassNginxWebSocket" ||
                    generateResult?.shellConfig.shellType === "BypassNginxJakartaWebSocket"
                  )
                }
                label={t("shellToolConfig.httpHeader")}
                text={`${(shellToolConfig as CommandShellToolConfig).headerName}: ${(shellToolConfig as CommandShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as CommandShellToolConfig).headerName}: ${(shellToolConfig as CommandShellToolConfig).headerValue}`}
              />
            </Fragment>
          )}
          {(generateResult?.shellConfig.shellTool === ShellToolType.Suo5 ||
            generateResult?.shellConfig.shellTool === ShellToolType.Suo5v2) && (
            <CopyableField
              label={t("shellToolConfig.suo5Header")}
              text={`${(shellToolConfig as Suo5ShellToolConfig).headerName}: ${(shellToolConfig as Suo5ShellToolConfig).headerValue}`}
              value={`${(shellToolConfig as Suo5ShellToolConfig).headerName}: ${(shellToolConfig as Suo5ShellToolConfig).headerValue}`}
            />
          )}
          {generateResult?.shellConfig.shellTool === ShellToolType.Proxy && (
            <CopyableField
              label={t("shellToolConfig.httpHeader")}
              text={`${(shellToolConfig as ProxyShellToolConfig).headerName}: ${(shellToolConfig as ProxyShellToolConfig).headerValue}`}
              value={`${(shellToolConfig as ProxyShellToolConfig).headerName}: ${(shellToolConfig as ProxyShellToolConfig).headerValue}`}
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
                label={t("shellToolConfig.neoreGeorgHeader")}
                text={`${(shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
                value={`${(shellToolConfig as NeoreGeorgShellToolConfig).headerName}: ${(shellToolConfig as NeoreGeorgShellToolConfig).headerValue}`}
              />
            </>
          )}
        </div>
        <Separator className="my-1" />
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
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
