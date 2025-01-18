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
import { Separator } from "@/components/ui/separator.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { downloadBytes } from "@/lib/utils.ts";
import {
  BehinderShellToolConfig,
  CommandShellToolConfig,
  GenerateResult,
  GodzillaShellToolConfig,
} from "@/types/shell.ts";
import { CircleHelpIcon, TriangleAlertIcon } from "lucide-react";
import { Fragment } from "react";

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

function FeedbackAlert() {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" type="button">
          <CircleHelpIcon /> 内存马利用失败 ？
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>内存马利用失败 ？</AlertDialogTitle>
          <AlertDialogDescription>
            <ol>
              <li>1. 尝试开启调试模式，重新生成内存马并注入，查看控制台或日志</li>
              <li>2. 如果出现异常堆栈信息，或未见异常，请截图当前生成界面以及异常日志，并尽可能描述目标环境进行反馈</li>
            </ol>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>取消</AlertDialogCancel>
          <AlertDialogAction
            onClick={() =>
              window.open(
                "https://github.com/ReaJason/MemShellParty/issues/new?template=%E5%86%85%E5%AD%98%E9%A9%AC%E7%94%9F%E6%88%90-bug-%E4%B8%8A%E6%8A%A5.md",
              )
            }
          >
            反馈
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function BasicInfo({ generateResult }: { generateResult?: GenerateResult }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          基础信息
          <FeedbackAlert />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2">
          <CopyableField label="目标服务" text={generateResult?.shellConfig.server} />
          <CopyableField label="内存马功能" text={generateResult?.shellConfig.shellTool} />
        </div>
        <CopyableField label="内存马挂载类型" text={generateResult?.shellConfig.shellType} />
        <CopyableField
          label="请求路径"
          text={generateResult?.injectorConfig.urlPattern}
          value={generateResult?.injectorConfig.urlPattern}
        />
        {generateResult?.shellConfig.shellTool === "Behinder" && (
          <Fragment>
            <CopyableField label="脚本类型" text="jsp" />
            <CopyableField label="加密类型" text="默认" />
            <CopyableField
              label="连接密码"
              text={(generateResult?.shellToolConfig as BehinderShellToolConfig).pass}
              value={(generateResult?.shellToolConfig as BehinderShellToolConfig).pass}
            />
            <CopyableField
              label="自定义请求头"
              text={`${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as BehinderShellToolConfig).headerValue}`}
            />
          </Fragment>
        )}
        {generateResult?.shellConfig.shellTool === "Godzilla" && (
          <Fragment>
            <CopyableField
              label="密码"
              text={(generateResult?.shellToolConfig as GodzillaShellToolConfig).pass}
              value={(generateResult?.shellToolConfig as GodzillaShellToolConfig).pass}
            />
            <CopyableField
              label="密钥"
              text={(generateResult?.shellToolConfig as GodzillaShellToolConfig).key}
              value={(generateResult?.shellToolConfig as GodzillaShellToolConfig).key}
            />
            <CopyableField label="有效载荷" text="JavaDynamicPayload" />
            <CopyableField label="加密器" text="JAVA_AES_BASE64" />
            <CopyableField
              label="请求配置 -> 请求头"
              text={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
              value={`${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerName}: ${(generateResult?.shellToolConfig as GodzillaShellToolConfig).headerValue}`}
            />
          </Fragment>
        )}
        {generateResult?.shellConfig.shellTool === "Command" && (
          <Fragment>
            <CopyableField
              label="接收命令请求参数"
              text={(generateResult?.shellToolConfig as CommandShellToolConfig).paramName}
              value={(generateResult?.shellToolConfig as CommandShellToolConfig).paramName}
            />
          </Fragment>
        )}
        <CopyableField
          label="注入器类名"
          value={generateResult?.injectorClassName}
          text={`${generateResult?.injectorClassName} (${generateResult?.injectorSize} bytes)`}
        />
        <CopyableField
          label="内存马类名"
          value={generateResult?.shellClassName}
          text={`${generateResult?.shellClassName} (${generateResult?.shellSize} bytes)`}
        />
      </CardContent>
    </Card>
  );
}

export function ShellResult({
  packResult,
  packMethod,
  generateResult,
}: { packResult: string; packMethod: string; generateResult?: GenerateResult }) {
  const showCode = packMethod === "JSP";
  const isAgent = packMethod.startsWith("Agent");
  return (
    <Tabs defaultValue="packResult">
      <TabsList className="grid w-full grid-cols-3">
        <TabsTrigger value="packResult">打包结果</TabsTrigger>
        <TabsTrigger value="shell">内存马类</TabsTrigger>
        <TabsTrigger value="injector">注入器类</TabsTrigger>
      </TabsList>
      <TabsContent value="packResult" className="my-4">
        <div className="mb-4">
          {generateResult && <BasicInfo generateResult={generateResult} />}
          {!generateResult && <QuickUsage />}
        </div>
        {!isAgent && (
          <CodeViewer
            code={packResult}
            wrapLongLines={!showCode}
            showLineNumbers={showCode}
            language={showCode ? "java" : "text"}
            height={400}
          />
        )}
        {isAgent && <AgentResult packResult={packResult} generateResult={generateResult} />}
      </TabsContent>
      <TabsContent value="shell" className="mt-4">
        <Alert>
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>反编译还在开发中，因此当前仅能看到 base64 编码格式</AlertDescription>
        </Alert>
        <div className="gap-4 my-2 flex items-center justify-end">
          {generateResult && (
            <Button
              size="sm"
              variant="outline"
              className="w-28"
              type="button"
              onClick={() => downloadBytes(generateResult?.shellBytesBase64Str, generateResult?.shellClassName)}
            >
              下载 Class
            </Button>
          )}
        </div>
        <CodeViewer
          showLineNumbers={false}
          wrapLongLines={true}
          code={generateResult?.shellBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
      <TabsContent value="injector" className="mt-4">
        <Alert>
          <TriangleAlertIcon className="h-4 w-4" />
          <AlertTitle>Warning</AlertTitle>
          <AlertDescription>反编译还在开发中，因此当前仅能看到 base64 编码格式</AlertDescription>
        </Alert>
        <div className="gap-4 my-2 flex items-center justify-end">
          {generateResult && (
            <Button
              size="sm"
              className="w-28"
              variant="outline"
              type="button"
              onClick={() => downloadBytes(generateResult?.injectorBytesBase64Str, generateResult?.injectorClassName)}
            >
              下载 Class
            </Button>
          )}
        </div>
        <CodeViewer
          showLineNumbers={false}
          wrapLongLines={true}
          code={generateResult?.injectorBytesBase64Str ?? ""}
          language="text"
        />
      </TabsContent>
    </Tabs>
  );
}
