import { UrlPatternTip } from "@/components/tips/url-pattern-tip.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { FormControl, FormDescription, FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Label } from "@/components/ui/label.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { Switch } from "@/components/ui/switch.tsx";
import { FormSchema } from "@/types/schema.ts";
import { MainConfig } from "@/types/shell.ts";
import { ServerIcon } from "lucide-react";

import { useState } from "react";
import { FormProvider, UseFormReturn } from "react-hook-form";

const JDKVersion = [
  { name: "Java6", value: "50" },
  { name: "Java8", value: "52" },
  { name: "Java9", value: "53" },
  { name: "Java11", value: "55" },
  { name: "Java17", value: "61" },
  { name: "Java21", value: "65" },
];

export function MainConfigCard({
  mainConfig,
  form,
  servers,
}: {
  mainConfig: MainConfig | undefined;
  form: UseFormReturn<FormSchema>;
  servers?: string[];
}) {
  const [shellToolMap, setShellToolMap] = useState<{ [toolName: string]: string[] }>();
  const [shellTools, setShellTools] = useState<string[]>([]);
  const [shellTypes, setShellTypes] = useState<string[]>([]);

  const handleServerChange = (value: string) => {
    if (mainConfig) {
      setShellToolMap(mainConfig[value]);
      setShellTools(Object.keys(mainConfig[value]));
      setShellTypes([]);
      form.resetField("shellTool");
      form.resetField("shellType");
    }
  };

  const handleShellToolChange = (value: string) => {
    const resetCommand = () => {
      form.resetField("commandParamName");
    };

    const resetGodzilla = () => {
      form.resetField("godzillaKey");
      form.resetField("godzillaPass");
      form.resetField("godzillaHeaderName");
      form.resetField("godzillaHeaderValue");
    };

    const resetBehinder = () => {
      form.resetField("behinderPass");
      form.resetField("behinderHeaderName");
      form.resetField("behinderHeaderValue");
    };

    if (shellToolMap) {
      setShellTypes(shellToolMap[value]);
      form.resetField("urlPattern");
      if (value === "Godzilla") {
        resetGodzilla();
      } else if (value === "Behinder") {
        resetBehinder();
      } else if (value === "Command") {
        resetCommand();
      }
    }
  };

  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <ServerIcon className="h-5" />
          <span>核心配置</span>
        </CardTitle>
      </CardHeader>
      <FormProvider {...form}>
        <CardContent>
          <div className="grid grid-cols-2 gap-2">
            <FormField
              control={form.control}
              name="server"
              render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel>目标服务</FormLabel>
                  <Select
                    onValueChange={(v) => {
                      field.onChange(v);
                      handleServerChange(v);
                    }}
                    value={field.value}
                  >
                    <FormControl>
                      <SelectTrigger className="h-8">
                        <SelectValue placeholder="请选择" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {servers?.map((server: string) => (
                        <SelectItem key={server} value={server}>
                          {server}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="targetJdkVersion"
              render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel>JRE(可选)</FormLabel>
                  <Select
                    onValueChange={(v) => {
                      if (Number.parseInt(v) >= 53) {
                        form.setValue("bypassJavaModule", true);
                      } else {
                        form.setValue("bypassJavaModule", false);
                      }
                      field.onChange(v);
                    }}
                    value={field.value}
                  >
                    <FormControl>
                      <SelectTrigger className="h-8">
                        <SelectValue placeholder="请选择" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {JDKVersion.map((v) => (
                        <SelectItem key={v.value} value={v.value}>
                          {v.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
          </div>
          <div className="flex items-center space-x-4 mt-2">
            <FormField
              control={form.control}
              name="debug"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch id="debug" checked={field.value} onCheckedChange={field.onChange} />
                  </FormControl>
                  <FormLabel htmlFor="debug">开启调试</FormLabel>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="bypassJavaModule"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2  space-y-0">
                  <FormControl>
                    <Switch id="bypassJavaModule" checked={field.value} onCheckedChange={field.onChange} />
                  </FormControl>
                  <Label htmlFor="bypassJavaModule">bypassJavaModule</Label>
                </FormItem>
              )}
            />
            <div className="flex items-center space-x-2">
              <Switch id="lambda" disabled />
              <Label htmlFor="lambda">Lambda 类名 (WIP)</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch id="obfuscate" disabled />
              <Label htmlFor="obfuscate">开启混淆 (WIP)</Label>
            </div>
          </div>
          <Separator className="mt-4 mb-2" />
          <FormField
            control={form.control}
            name="shellClassName"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel>内存马类名（可选）</FormLabel>
                <Input id="shellClassName" {...field} placeholder="请输入" className="h-8" />
              </FormItem>
            )}
          />
          <div className="grid grid-cols-3 gap-2 mt-2">
            <FormField
              control={form.control}
              name="shellTool"
              render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel>内存马工具类型</FormLabel>
                  <Select
                    value={field.value}
                    onValueChange={(value: string) => {
                      field.onChange(value);
                      handleShellToolChange(value);
                    }}
                  >
                    <FormControl>
                      <SelectTrigger className="h-8">
                        <SelectValue placeholder="请选择" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {shellTools.length ? (
                        shellTools.map((v) => (
                          <SelectItem key={v} value={v}>
                            {v}
                          </SelectItem>
                        ))
                      ) : (
                        <SelectItem value=" ">请先选择目标服务</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="shellType"
              render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel>内存马挂载类型</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger className="h-8">
                        <SelectValue placeholder="请选择" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {shellTypes.length ? (
                        shellTypes.map((v) => (
                          <SelectItem key={v} value={v}>
                            {v}
                          </SelectItem>
                        ))
                      ) : (
                        <SelectItem value=" ">请先选择内存马工具类型</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="urlPattern"
              render={({ field }) => (
                <FormItem className="flex flex-col mt-1">
                  <Label className="flex items-center">
                    请求路径 <UrlPatternTip />
                  </Label>
                  <Input {...field} placeholder="请输入" className="h-8" />
                </FormItem>
              )}
            />
          </div>
          <div className="mt-2">
            {form.getValues().shellTool === "Godzilla" && (
              <div className="space-y-1">
                <Label>Godzilla 配置</Label>
                <div className="grid grid-cols-2 gap-2">
                  <FormField
                    control={form.control}
                    name="godzillaPass"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">密码：</Label>
                        <Input {...field} placeholder="Pass" className="h-8" />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="godzillaKey"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">密钥：</Label>
                        <Input {...field} placeholder="Key" className="h-8" />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="godzillaHeaderName"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">请求头键：</Label>
                        <Input {...field} placeholder="Header Name" className="h-8" />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="godzillaHeaderValue"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">请求头值：</Label>
                        <Input {...field} placeholder="Header Value" className="h-8" />
                      </FormItem>
                    )}
                  />
                </div>
              </div>
            )}
            {form.getValues().shellTool === "Behinder" && (
              <div className="space-y-1">
                <Label>Behinder 配置</Label>
                <div className="grid grid-cols-2 gap-2">
                  <FormField
                    control={form.control}
                    name="behinderPass"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">密码：</Label>
                        <Input {...field} placeholder="Pass" className="h-8" />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="behinderHeaderName"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">请求头键：</Label>
                        <Input {...field} placeholder="Header Name" className="h-8" />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="behinderHeaderValue"
                    render={({ field }) => (
                      <FormItem className="space-y-1 flex items-center justify-start">
                        <Label className="text-xs whitespace-nowrap w-1/2">请求头值：</Label>
                        <Input {...field} placeholder="Header Value" className="h-8" />
                      </FormItem>
                    )}
                  />
                </div>
              </div>
            )}
            {form.getValues().shellTool === "Command" && (
              <FormField
                control={form.control}
                name="commandParamName"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>请求参数</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="请输入" className="h-8" />
                    </FormControl>
                    <FormDescription>填写接收命令的请求参数，例如填 cmd 即 `?cmd=whoami` 来执行命令</FormDescription>
                  </FormItem>
                )}
              />
            )}
          </div>
          <Separator className="mt-4 mb-2" />
          <FormField
            control={form.control}
            name="injectorClassName"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel>注入器类名（可选）</FormLabel>
                <Input id="injectorClassName" {...field} placeholder="请输入" className="h-8" />
              </FormItem>
            )}
          />
          <div className="space-y-1 mt-2">
            <Label htmlFor="interface" className="flex items-center gap-2">
              注入器类继承（可选）(WIP)
            </Label>
            <Select disabled>
              <SelectTrigger id="interface" className="h-8">
                <SelectValue placeholder="请选择" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="JDK_AbstractTranslet">JDK_AbstractTranslet</SelectItem>
                <SelectItem value="XALAN_AbstractTranslet">XALAN_AbstractTranslet</SelectItem>
                <SelectItem value="FASTJSON_GroovyASTTransformation">FASTJSON_GroovyASTTransformation</SelectItem>
                <SelectItem value="SnakeYaml_ScriptEngineFactory">SnakeYaml_ScriptEngineFactory</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </FormProvider>
    </Card>
  );
}
