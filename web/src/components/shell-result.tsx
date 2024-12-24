import { CodeViewer } from "@/components/code-viewer.tsx";
import { CopyableField } from "@/components/copyable-field.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Label } from "@/components/ui/label.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.tsx";
import { downloadJavaClass } from "@/lib/utils.ts";
import { GenerateResult } from "@/types/shell.ts";
import { TicketsIcon, TriangleAlertIcon } from "lucide-react";

export function ShellResult({
  packResult,
  packMethod,
  generateResult,
}: { packResult: string; packMethod: string; generateResult?: GenerateResult }) {
  const showCode = packMethod === "JSP";
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
            {generateResult && (
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
            <CodeViewer
              code={packResult}
              wrapLongLines={!showCode}
              showLineNumbers={showCode}
              language={showCode ? "java" : "text"}
            />
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
                  <div className="flex items-center">
                    <Label>内存马类名：</Label>
                    <p>{generateResult?.shellClassName}</p>
                  </div>
                  <div className="flex items-center">
                    <Label>内存马字节码大小：</Label>
                    <p>{generateResult?.shellSize ?? 0} bytes</p>
                  </div>
                </div>
              )}
              <Button
                size="sm"
                className="h-8 gap-1"
                type="button"
                onClick={() => downloadJavaClass(generateResult?.shellBytesBase64Str, generateResult?.shellClassName)}
              >
                下载 Class
              </Button>
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
                  <div className="flex items-center">
                    <Label>注入器类名：</Label>
                    <p>{generateResult?.injectorClassName}</p>
                  </div>
                  <div className="flex items-center">
                    <Label>注入器字节码大小：</Label>
                    <p>{generateResult?.injectorSize ?? 0} bytes</p>
                  </div>
                </div>
              )}
              <Button
                size="sm"
                className="h-8 gap-1"
                type="button"
                onClick={() =>
                  downloadJavaClass(generateResult?.injectorBytesBase64Str, generateResult?.injectorClassName)
                }
              >
                下载 Class
              </Button>
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
