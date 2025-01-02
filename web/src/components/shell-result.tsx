import { CodeViewer } from "@/components/code-viewer.tsx";
import { CopyableField } from "@/components/copyable-field.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Label } from "@/components/ui/label.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { downloadBytes } from "@/lib/utils.ts";
import { GenerateResult } from "@/types/shell.ts";
import { TicketsIcon, TriangleAlertIcon } from "lucide-react";

function AgentResult({ packResult, generateResult }: { packResult: string; generateResult?: GenerateResult }) {
  return (
    <section>
      <ol className="list-decimal list-inside space-y-4">
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
        <h2 className="text-2xl font-bold mb-4">使用方法：</h2>
        <li>将 MemShellAgent.jar 和 jattach 移动到容器中（如果测试环境使用容器部署）</li>
        <li>获取目标 jvm 的进程 pid （使用 jps 或 ps）</li>
        <li>执行命令进行注入：/path/to/jattach pid load instrument false /path/to/agent.jar</li>
        <li>尝试连接测试</li>
      </ol>
    </section>
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
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-md flex items-center gap-2">
          <TicketsIcon className="h-5" />
          FBI
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="packResult">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="packResult">打包结果</TabsTrigger>
            <TabsTrigger value="shell">内存马类</TabsTrigger>
            <TabsTrigger value="injector">注入器类</TabsTrigger>
          </TabsList>
          <TabsContent value="packResult" className="mt-4">
            {generateResult && !isAgent && (
              <div className="gap-4 my-2">
                <CopyableField
                  label="注入器类名"
                  value={generateResult?.injectorClassName}
                  size={generateResult?.injectorSize}
                />
                <CopyableField
                  label="内存马类名"
                  value={generateResult?.shellClassName}
                  size={generateResult?.shellSize}
                />
              </div>
            )}
            {!isAgent && (
              <CodeViewer
                code={packResult}
                wrapLongLines={!showCode}
                showLineNumbers={showCode}
                language={showCode ? "java" : "text"}
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
            <div className="gap-4 my-2 flex items-center justify-between">
              {generateResult && (
                <div>
                  <div className="flex items-center text-sm">
                    <Label>内存马类名：</Label>
                    <p>{generateResult?.shellClassName}</p>
                  </div>
                  <div className="flex items-center text-sm">
                    <Label>内存马字节码大小：</Label>
                    <p>{generateResult?.shellSize ?? 0} bytes</p>
                  </div>
                </div>
              )}
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
            <div className="gap-4 my-2 flex items-center justify-between">
              {generateResult && (
                <div>
                  <div className="flex items-center text-sm">
                    <Label>注入器类名：</Label>
                    <p>{generateResult?.injectorClassName}</p>
                  </div>
                  <div className="flex items-center text-sm">
                    <Label>注入器字节码大小：</Label>
                    <p>{generateResult?.injectorSize ?? 0} bytes</p>
                  </div>
                </div>
              )}
              {generateResult && (
                <Button
                  size="sm"
                  className="w-28"
                  variant="outline"
                  type="button"
                  onClick={() =>
                    downloadBytes(generateResult?.injectorBytesBase64Str, generateResult?.injectorClassName)
                  }
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
      </CardContent>
    </Card>
  );
}
