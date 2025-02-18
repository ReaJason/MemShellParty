import { CodeViewer } from "@/components/code-viewer.tsx";
import { CopyableField } from "@/components/copyable-field.tsx";
import { QuickUsage } from "@/components/quick-usage.tsx";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { downloadBytes } from "@/lib/utils.ts";
import {
  AntSwordShellToolConfig,
  BehinderShellToolConfig,
  CommandShellToolConfig,
  GenerateResult,
  GodzillaShellToolConfig,
  Suo5ShellToolConfig,
} from "@/types/shell.ts";
import { TFunction } from "i18next";
import { CircleHelpIcon, TicketCheckIcon, TriangleAlertIcon } from "lucide-react";
import { Fragment, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

function AgentResult({ packResult, generateResult }: { packResult: string; generateResult?: GenerateResult }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>使用方法</CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal list-inside space-y-4 text-sm">
          <li className="flex items-center justify-between">
            <span>下载 MemShellAgent.jar</span>
            <Button
              size="sm"
              variant="outline"
              className="w-28"
              type="button"
              onClick={() =>
                downloadBytes(
                  packResult,
                  undefined,
                  `${generateResult?.shellConfig.server}${generateResult?.shellConfig.shellTool}MemShellAgent`,
                )
              }
            >
              下载 Jar
            </Button>
          </li>
          <li className="flex items-center justify-between">
            <span>下载 Jattach 工具（后期考虑直接封装在 Jar 中）</span>
            <Button
              size="sm"
              variant="outline"
              className="w-28"
              type="button"
              onClick={() => window.open("https://github.com/jattach/jattach/releases")}
            >
              下载 Jattach
            </Button>
          </li>
          <Separator />
          <li>将 MemShellAgent.jar 和 jattach 移动到容器中（如果测试环境使用容器部署）</li>
          <li>获取目标 jvm 的进程 pid （使用 jps 或 ps）</li>
          <li>执行命令进行注入：/path/to/jattach pid load instrument false /path/to/agent.jar</li>
          <li>尝试利用内存马</li>
        </ol>
      </CardContent>
    </Card>
  );
}

function JarResult({ packResult, generateResult }: { packResult: string; generateResult?: GenerateResult }) {
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

function FeedbackAlert() {
  const { t } = useTranslation();
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" type="button">
          <CircleHelpIcon /> {t("shellNotWork.title")}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t("shellNotWork.title")}</AlertDialogTitle>
          <AlertDialogDescription>
            <ol>
              <li>{t("shellNotWork.step1")}</li>
              <li>{t("shellNotWork.step2")}</li>
            </ol>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
          <AlertDialogAction
            onClick={() =>
              window.open(
                "https://github.com/ReaJason/MemShellParty/issues/new?template=%E5%86%85%E5%AD%98%E9%A9%AC%E7%94%9F%E6%88%90-bug-%E4%B8%8A%E6%8A%A5.md",
              )
            }
          >
            {t("feedback")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function BasicInfo({ generateResult }: { generateResult?: GenerateResult }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="text-md flex items-center gap-2">
            <TicketCheckIcon className="h-5" />
            <span>{t("generateResult.basicInfo")}</span>
          </div>
          <FeedbackAlert />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2">
          <CopyableField label={t("mainConfig.server")} text={generateResult?.shellConfig.server} />
          <CopyableField label={t("mainConfig.shellTool")} text={generateResult?.shellConfig.shellTool} />
        </div>
        <CopyableField label={t("mainConfig.shellMountType")} text={generateResult?.shellConfig.shellType} />
        <CopyableField
          label={t("mainConfig.urlPattern")}
          text={generateResult?.injectorConfig.urlPattern}
          value={generateResult?.injectorConfig.urlPattern}
        />
        {generateResult?.shellConfig.shellTool === "Behinder" && (
          <Fragment>
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
          </Fragment>
        )}
        {generateResult?.shellConfig.shellTool === "Godzilla" && (
          <Fragment>
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
            <CopyableField label={t("shellToolConfig.godzillaPayload")} text="JavaDynamicPayload" />
            <CopyableField label={t("shellToolConfig.godzillaEncryptor")} text="JAVA_AES_BASE64" />
            <CopyableField
              label={t("shellToolConfig.godzillaHeader")}
              text={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
            />
          </Fragment>
        )}
        {generateResult?.shellConfig.shellTool === "Command" && (
          <Fragment>
            <CopyableField
              label={t("shellToolConfig.paramName")}
              text={(generateResult?.shellToolConfig as CommandShellToolConfig).paramName}
              value={(generateResult?.shellToolConfig as CommandShellToolConfig).paramName}
            />
          </Fragment>
        )}
        {generateResult?.shellConfig.shellTool === "Suo5" && (
          <Fragment>
            <CopyableField
              label={t("shellToolConfig.suo5Header")}
              text={`${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as Suo5ShellToolConfig).headerValue}`}
            />
          </Fragment>
        )}
        {generateResult?.shellConfig.shellTool === "AntSword" && (
          <Fragment>
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
          </Fragment>
        )}
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
      </CardContent>
    </Card>
  );
}

function MultiPackResult({
  allPackResults,
  packMethod,
  t,
}: {
  allPackResults: object | undefined;
  packMethod: string;
  t: TFunction;
}) {
  const showCode = packMethod === "JSP";
  const packMethods = Object.keys(allPackResults ?? {});
  const [selectedMethod, setSelectedMethod] = useState(packMethods[0]);
  const [packResult, setPackResult] = useState(allPackResults?.[selectedMethod as keyof typeof allPackResults] ?? "");
  return (
    <Fragment>
      <CodeViewer
        code={packResult ?? ""}
        header={
          <div className="flex items-center justify-between text-xs gap-2">
            <Select
              onValueChange={(value) => {
                setSelectedMethod(value);
                setPackResult(allPackResults?.[value as keyof typeof allPackResults] ?? "");
              }}
              value={selectedMethod}
            >
              <SelectTrigger className="h-7 text-xs [&_svg]:h-4 [&_svg]:w-4">
                <span className="text-muted-foreground">{t("packageConfig.title")}:&nbsp;</span>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {packMethods.map((method) => (
                  <SelectItem key={method} value={method} className="text-xs">
                    {method}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <span className="text-muted-foreground">({packResult?.length})</span>
          </div>
        }
        wrapLongLines={!showCode}
        showLineNumbers={showCode}
        language={showCode ? "java" : "text"}
        height={350}
      />
    </Fragment>
  );
}

function renderResultComponent(
  packResult: string | undefined,
  allPackResults: Map<string, string> | undefined,
  packMethod: string,
  t: TFunction,
  generateResult?: GenerateResult,
) {
  const showCode = packMethod === "JSP";
  const isAgent = packMethod.startsWith("Agent");
  const isJar = packMethod === "Jar";
  if (allPackResults) {
    return <MultiPackResult allPackResults={allPackResults} packMethod={packMethod} t={t} />;
  }

  if (isAgent) {
    return <AgentResult packResult={packResult ?? ""} generateResult={generateResult} />;
  }
  if (isJar) {
    return <JarResult packResult={packResult ?? ""} generateResult={generateResult} />;
  }
  if (!isAgent && !isJar) {
    return (
      <Fragment>
        <CodeViewer
          code={packResult ?? ""}
          header={
            <div className="flex items-center justify-between text-xs gap-2">
              <span>
                {t("packageConfig.title")}：{packMethod}
              </span>
              <span className="text-muted-foreground">({packResult?.length})</span>
            </div>
          }
          wrapLongLines={!showCode}
          showLineNumbers={showCode}
          language={showCode ? "java" : "text"}
          height={350}
        />
      </Fragment>
    );
  }
  return null;
}

export function ShellResult({
  packResult,
  allPackResults,
  packMethod,
  generateResult,
}: {
  packResult: string | undefined;
  allPackResults: Map<string, string> | undefined;
  packMethod: string;
  generateResult?: GenerateResult;
}) {
  const { t } = useTranslation();
  if (!generateResult) {
    return <QuickUsage />;
  }
  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-3">
        <TabsTrigger value="packResult">{t("generateResult.title1")}</TabsTrigger>
        <TabsTrigger value="shell">{t("generateResult.title2")}</TabsTrigger>
        <TabsTrigger value="injector">{t("generateResult.title3")}</TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="my-4">
        <div className="mb-4">
          <BasicInfo generateResult={generateResult} />
        </div>
        {renderResultComponent(packResult, allPackResults, packMethod, t, generateResult)}
      </TabsContent>
      <TabsContent value="shell" className="mt-4">
        <Alert>
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>{t("tips.decompileTip")}</AlertDescription>
        </Alert>
        <div className="gap-4 my-2 flex items-center justify-end">
          <Button
            size="sm"
            variant="outline"
            className="w-28"
            type="button"
            onClick={() => {
              if (!generateResult?.shellBytesBase64Str) {
                toast.warning(t("tips.shellBytesEmpty"));
                return;
              }
              downloadBytes(generateResult?.shellBytesBase64Str, generateResult?.shellClassName);
            }}
          >
            {t("download")} Class
          </Button>
        </div>
        <CodeViewer
          showLineNumbers={false}
          header={<div className="text-xs">{generateResult?.shellClassName}</div>}
          wrapLongLines={true}
          height={600}
          code={generateResult?.shellBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
      <TabsContent value="injector" className="mt-4">
        <Alert>
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>{t("tips.decompileTip")}</AlertDescription>
        </Alert>
        <div className="gap-4 my-2 flex items-center justify-end">
          <Button
            size="sm"
            className="w-28"
            variant="outline"
            type="button"
            onClick={() => {
              if (!generateResult?.injectorBytesBase64Str) {
                toast.warning(t("tips.shellBytesEmpty"));
                return;
              }
              downloadBytes(generateResult?.injectorBytesBase64Str, generateResult?.injectorClassName);
            }}
          >
            {t("download")} Class
          </Button>
        </div>
        <CodeViewer
          showLineNumbers={false}
          wrapLongLines={true}
          header={<div className="text-xs">{generateResult?.injectorClassName}</div>}
          height={600}
          code={generateResult?.injectorBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
    </Tabs>
  );
}
