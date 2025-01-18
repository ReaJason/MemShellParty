import { UrlPatternTip } from "@/components/tips/url-pattern-tip.tsx";
import { FormControl, FormDescription, FormField, FormItem, FormLabel } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Label } from "@/components/ui/label.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import { Switch } from "@/components/ui/switch.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FormSchema } from "@/types/schema.ts";
import { MainConfig } from "@/types/shell.ts";

import { JreTip } from "@/components/tips/jre-tip.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { cn } from "@/lib/utils.ts";
import { ArrowUpRightIcon, ServerIcon } from "lucide-react";
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
  const [shellTools, setShellTools] = useState<string[]>(["Behinder", "Godzilla", "Command"]);
  const [shellTypes, setShellTypes] = useState<string[]>([]);
  const shellTool = form.watch("shellTool");

  const handleServerChange = (value: string) => {
    if (mainConfig) {
      const newShellToolMap = mainConfig[value];
      setShellToolMap(newShellToolMap);
      const newShellTools = Object.keys(newShellToolMap);
      setShellTools(newShellTools);
      if (newShellTools.length > 0) {
        const firstTool = newShellTools[0];
        setShellTypes(newShellToolMap[firstTool]);
        form.setValue("shellTool", firstTool);
      } else {
        setShellTypes([]);
      }
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
      form.resetField("shellType");
      form.resetField("shellClassName");
      form.resetField("injectorClassName");
      if (value === "Godzilla") {
        resetGodzilla();
      } else if (value === "Behinder") {
        resetBehinder();
      } else if (value === "Command") {
        resetCommand();
      }
    }
    form.setValue("shellTool", value);
  };

  return (
    <FormProvider {...form}>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-md flex items-center gap-2">
            <ServerIcon className="h-5" />
            <span>生成配置</span>
          </CardTitle>
        </CardHeader>
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
                  <FormDescription className="flex items-center">
                    下拉列表找不到目标服务 ？
                    <a
                      href="https://github.com/ReaJason/MemShellParty/issues/new?template=%E8%AF%B7%E6%B1%82%E9%80%82%E9%85%8D.md"
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center underline"
                    >
                      请求适配
                      <ArrowUpRightIcon className="h-4" />
                    </a>
                  </FormDescription>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="targetJdkVersion"
              render={({ field }) => (
                <FormItem className="flex flex-col mt-1">
                  <Label className="flex items-center">
                    目标 JRE 版本(可选) <JreTip />
                  </Label>
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
          <div className="flex gap-4 mt-4">
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
                  <Label htmlFor="bypassJavaModule">绕过 Java 模块系统限制</Label>
                </FormItem>
              )}
            />
          </div>
        </CardContent>
      </Card>
      <Tabs
        value={shellTool}
        onValueChange={(v) => {
          handleShellToolChange(v);
        }}
        className="w-full"
      >
        <TabsList className={cn("grid w-full", `grid-cols-${shellTools.length}`)}>
          {shellTools.map((shellTool) => (
            <TabsTrigger key={shellTool} value={shellTool}>
              {shellTool}
            </TabsTrigger>
          ))}
        </TabsList>
        <BehinderTabContent form={form} shellTypes={shellTypes} />
        <GodzillaTabContent form={form} shellTypes={shellTypes} />
        <CommandTabContent form={form} shellTypes={shellTypes} />
      </Tabs>
    </FormProvider>
  );
}

function ShellTypeFormField({ form, shellTypes }: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  return (
    <FormProvider {...form}>
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
              <SelectContent key={shellTypes.join(",")}>
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
    </FormProvider>
  );
}

function UrlPatternFormField({ form }: { form: UseFormReturn<FormSchema> }) {
  return (
    <FormProvider {...form}>
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
    </FormProvider>
  );
}

function OptionalClassFormField({ form }: { form: UseFormReturn<FormSchema> }) {
  return (
    <FormProvider {...form}>
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
    </FormProvider>
  );
}

function BehinderTabContent({ form, shellTypes }: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  return (
    <FormProvider {...form}>
      <TabsContent value="Behinder">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <FormField
              control={form.control}
              name="behinderPass"
              render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel>连接密码</FormLabel>
                  <Input {...field} placeholder="Pass" className="h-8" />
                </FormItem>
              )}
            />
            <div className="grid grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="behinderHeaderName"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>请求头键</FormLabel>
                    <Input {...field} placeholder="Header Name" className="h-8" />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="behinderHeaderValue"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>请求头值</FormLabel>
                    <Input {...field} placeholder="Header Value" className="h-8" />
                  </FormItem>
                )}
              />
            </div>
            <OptionalClassFormField form={form} />
          </CardContent>
        </Card>
      </TabsContent>
    </FormProvider>
  );
}

function GodzillaTabContent({ form, shellTypes }: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  return (
    <FormProvider {...form}>
      <TabsContent value="Godzilla">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <FormField
                control={form.control}
                name="godzillaPass"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>密码</FormLabel>
                    <Input {...field} placeholder="Pass" className="h-8" />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="godzillaKey"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>密钥</FormLabel>
                    <Input {...field} placeholder="Key" className="h-8" />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="godzillaHeaderName"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>请求头键</FormLabel>
                    <Input {...field} placeholder="Header Name" className="h-8" />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="godzillaHeaderValue"
                render={({ field }) => (
                  <FormItem className="space-y-1">
                    <FormLabel>请求头值</FormLabel>
                    <Input {...field} placeholder="Header Value" className="h-8" />
                  </FormItem>
                )}
              />
            </div>
            <OptionalClassFormField form={form} />
          </CardContent>
        </Card>
      </TabsContent>
    </FormProvider>
  );
}

function CommandTabContent({ form, shellTypes }: { form: UseFormReturn<FormSchema>; shellTypes: Array<string> }) {
  return (
    <FormProvider {...form}>
      <TabsContent value="Command">
        <Card>
          <CardContent className="space-y-2 mt-4">
            <div className="grid grid-cols-2 gap-2">
              <ShellTypeFormField form={form} shellTypes={shellTypes} />
              <UrlPatternFormField form={form} />
            </div>
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
            <OptionalClassFormField form={form} />
          </CardContent>
        </Card>
      </TabsContent>
    </FormProvider>
  );
}
