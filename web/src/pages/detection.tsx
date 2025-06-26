/** biome-ignore-all lint/suspicious/noThenProperty: no way */

import { yupResolver } from "@hookform/resolvers/yup";
import { AlertTriangle, Trash2 } from "lucide-react";
import * as React from "react";
import { useId, useState } from "react";
import { Controller, useFieldArray, useForm } from "react-hook-form";
import * as yup from "yup";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormFieldItem,
  FormFieldLabel,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

// --- 类型定义 ---

// 回显方式
type EchoMethod = "header" | "body" | "dnslog" | "httplog" | "sleep";

// 回显内容
type EchoContent = "middleware" | "os" | "jdk" | "bytecode" | "command";

// 表单值的完整类型
interface PayloadFormValues {
  echoMethod: EchoMethod;
  echoContent?: EchoContent;
  // Header
  headerName?: string;
  // DNSLog / HTTPLog
  logAddress?: string;
  middlewareType?: "tomcat" | "jetty" | "springboot" | "weblogic";
  paramSource?: "builtin" | "requestParam" | "requestHeader";
  requestParamName?: string;
  requestHeaderName?: string;
  bytecodeBase64?: string;
  command?: string;
  // Sleep 选项
  sleepMiddleware?: "tomcat" | "jetty" | "springboot" | "weblogic";
  sleepMiddlewareDelay?: number;
  sleepOsDelays?: { os: "linux" | "windows" | "macos"; delay: number }[];
  sleepJdkDetectionType?: "version" | "type";
  sleepJdkVersion?: "8" | "11" | "17";
  sleepJdkType?: "jdk" | "jre";
  sleepJdkDelay?: number;
  sleepBytecodeSuccessDelay?: number;
}

const formSchema = yup.object().shape({
  echoMethod: yup.string().required("请选择一种回显方式"),

  // 条件：当 echoMethod 是 'header'
  headerName: yup.string().when("echoMethod", {
    is: "header",
    then: (schema) => schema.required("必须填写 Header Name"),
    otherwise: (schema) => schema.optional(),
  }),

  // 条件：当 echoMethod 是 'dnslog' 或 'httplog'
  logAddress: yup.string().when("echoMethod", {
    is: (val: EchoMethod) => val === "dnslog" || val === "httplog",
    then: (schema) => schema.required("必须填写 Log 地址"),
    otherwise: (schema) => schema.optional(),
  }),

  // 只有在选择了具体内容时才需要
  echoContent: yup.string().required("请选择回显内容"),

  // --- 嵌套条件验证 ---

  // 中间件类型在特定组合下是必须的
  middlewareType: yup.string().when(["echoMethod", "echoContent"], {
    is: (echoMethod: EchoMethod, echoContent: EchoContent) =>
      (echoMethod === "header" || echoMethod === "body") &&
      (echoContent === "os" || echoContent === "jdk" || echoContent === "bytecode"),
    then: (schema) => schema.required("请选择中间件类型"),
    otherwise: (schema) => schema.optional(),
  }),

  // 字节码相关
  paramSource: yup.string().when(["echoMethod", "echoContent"], {
    is: (echoMethod: EchoMethod, echoContent: EchoContent) =>
      (echoMethod === "header" || echoMethod === "body") && echoContent === "bytecode",
    then: (schema) => schema.required("请选择字节码来源"),
    otherwise: (schema) => schema.optional(),
  }),
  bytecodeBase64: yup.string().when(["echoContent", "paramSource"], {
    is: (echoContent: EchoContent, paramSource: string) => echoContent === "bytecode" && paramSource === "builtin",
    then: (schema) => schema.required("必须填写字节码 Base64"),
    otherwise: (schema) => schema.optional(),
  }),
  requestParamName: yup.string().when("paramSource", {
    is: (paramSource: string) => paramSource === "requestParam",
    then: (schema) => schema.required("必须填写 Request Param Name"),
    otherwise: (schema) => schema.optional(),
  }),
  requestHeaderName: yup.string().when("paramSource", {
    is: (paramSource: string) => paramSource === "requestHeader",
    then: (schema) => schema.required("必须填写 Request Header Name"),
    otherwise: (schema) => schema.optional(),
  }),
  command: yup.string().when("echoContent", {
    is: (echoContent: EchoContent) => echoContent === "command",
    then: (schema) => schema.required("必须填写执行的命令"),
    otherwise: (schema) => schema.optional(),
  }),

  // --- Sleep 相关验证 ---
  sleepMiddleware: yup.string().when(["echoMethod", "echoContent"], {
    is: (method: string, content: string) => method === "sleep" && content === "middleware",
    then: (s) => s.required("请选择目标中间件"),
    otherwise: (s) => s.optional(),
  }),
  sleepMiddlewareDelay: yup.number().when(["echoMethod", "echoContent"], {
    is: (method: string, content: string) => method === "sleep" && content === "middleware",
    then: (s) => s.required("请填写延迟时间").min(1, "延迟至少为 1 秒").typeError("请输入有效的秒数"),
    otherwise: (s) => s.optional(),
  }),
  sleepOsDelays: yup.array().when(["echoMethod", "echoContent"], {
    is: (method: string, content: string) => method === "sleep" && content === "os",
    then: (s) =>
      s
        .of(
          yup.object().shape({
            os: yup.string().required(),
            delay: yup.number().required("请填写延迟时间").min(1, "延迟至少为 1 秒").typeError("请输入有效的秒数"),
          }),
        )
        .min(1, "至少需要一个操作系统延迟配置"),
    otherwise: (s) => s.optional(),
  }),
  sleepJdkDetectionType: yup.string().when(["echoMethod", "echoContent"], {
    is: (method: string, content: string) => method === "sleep" && content === "jdk",
    then: (s) => s.required("请选择 JDK 探测类型"),
    otherwise: (s) => s.optional(),
  }),
  sleepJdkVersion: yup.string().when("sleepJdkDetectionType", {
    is: "version",
    then: (s) => s.required("请选择 JDK 版本"),
    otherwise: (s) => s.optional(),
  }),
  sleepJdkType: yup.string().when("sleepJdkDetectionType", {
    is: "type",
    then: (s) => s.required("请选择 JDK/JRE 类型"),
    otherwise: (s) => s.optional(),
  }),
  sleepJdkDelay: yup.number().when(["echoMethod", "echoContent"], {
    is: (method: string, content: string) => method === "sleep" && content === "jdk",
    then: (s) => s.required("请填写延迟时间").min(1, "延迟至少为 1 秒").typeError("请输入有效的秒数"),
    otherwise: (s) => s.optional(),
  }),
  sleepBytecodeSuccessDelay: yup.number().when(["echoMethod", "echoContent"], {
    is: (method: string, content: string) => method === "sleep" && content === "bytecode",
    then: (s) => s.required("请填写延迟时间").min(1, "延迟至少为 1 秒").typeError("请输入有效的秒数"),
    otherwise: (s) => s.optional(),
  }),
});

export default function EchoPayloadGenerator() {
  const form = useForm<PayloadFormValues>({
    resolver: yupResolver(formSchema) as any,
    defaultValues: {
      echoMethod: "header",
      echoContent: undefined,
      headerName: "X-Echo",
      logAddress: "",
      middlewareType: undefined,
      paramSource: "builtin",
      requestHeaderName: "X-Data",
      requestParamName: "payload",
      sleepOsDelays: [{ os: "linux", delay: 5 }],
      sleepJdkDetectionType: "version",
      sleepJdkType: "jdk",
      sleepJdkVersion: "8",
      sleepJdkDelay: 5,
      sleepBytecodeSuccessDelay: 5,
      sleepMiddlewareDelay: 5,
    },
  });

  const { fields, append, remove } = useFieldArray({
    control: form.control,
    name: "sleepOsDelays",
  });

  // 监视表单值的变化以动态渲染 UI
  const watchedEchoMethod = form.watch("echoMethod");
  const watchedEchoContent = form.watch("echoContent");
  const watchedParamSource = form.watch("paramSource");
  const watchedSleepJdkDetectionType = form.watch("sleepJdkDetectionType");

  // 重置子选项
  React.useEffect(() => {
    form.setValue("echoContent", undefined);
  }, [form.setValue]);

  function onSubmit(values: PayloadFormValues) {
    // 在这里可以构建最终的 Payload
    console.log("Form Submitted:", values);
  }

  // --- 动态内容渲染 ---
  const [isFile, setIsFile] = useState(false);
  const optionOneId = useId();
  const optionTwoId = useId();

  const renderContentOptions = () => {
    const baseOptions: { value: EchoContent; label: string }[] = [
      { value: "middleware", label: "中间件类型" },
      { value: "os", label: "操作系统类型" },
      { value: "jdk", label: "JDK 信息" },
      { value: "command", label: "命令执行" },
      { value: "bytecode", label: "自定义字节码执行" },
    ];

    let filteredOptions = baseOptions;

    // 根据规则过滤选项
    if (watchedEchoMethod === "header" || watchedEchoMethod === "body") {
      filteredOptions = baseOptions.filter((opt) => opt.value !== "middleware");
    }

    if (watchedEchoMethod === "dnslog" || watchedEchoMethod === "httplog" || watchedEchoMethod === "sleep") {
      filteredOptions = baseOptions.filter((opt) => opt.value !== "command" && opt.value !== "bytecode");
    }

    return (
      <FormField
        control={form.control}
        name="echoContent"
        render={({ field }) => (
          <FormFieldItem>
            <FormFieldLabel>回显内容</FormFieldLabel>
            <Select onValueChange={field.onChange} defaultValue={field.value}>
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder="请选择要回显的内容..." />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {filteredOptions.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormMessage />
          </FormFieldItem>
        )}
      />
    );
  };

  const renderDynamicFields = () => {
    // --- Response Header / Body ---
    if ((watchedEchoMethod === "header" || watchedEchoMethod === "body") && watchedEchoContent) {
      return (
        <>
          {watchedEchoContent === "bytecode" && (
            <div className="space-y-4 pt-4 border-t mt-4">
              <FormField
                control={form.control}
                name="paramSource"
                render={({ field }) => (
                  <FormFieldItem className="space-y-2">
                    <FormFieldLabel>字节码来源</FormFieldLabel>
                    <FormControl>
                      <RadioGroup onValueChange={field.onChange} defaultValue={field.value} className="flex gap-4">
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="builtin" />
                          </FormControl>
                          <FormLabel className="font-normal">内嵌字节码</FormLabel>
                        </FormItem>
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="requestHeader" />
                          </FormControl>
                          <FormLabel className="font-normal">通过 Request Header 传递</FormLabel>
                        </FormItem>
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="requestParam" />
                          </FormControl>
                          <FormLabel className="font-normal">通过 Request Param 传递</FormLabel>
                        </FormItem>
                      </RadioGroup>
                    </FormControl>
                    <FormMessage />
                  </FormFieldItem>
                )}
              />
              {watchedParamSource === "builtin" && (
                <FormField
                  control={form.control}
                  name="bytecodeBase64"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>字节码 Base64</FormFieldLabel>
                      <RadioGroup
                        value={isFile ? "file" : "base64"}
                        onValueChange={(value) => {
                          field.onChange("");
                          setIsFile(value === "file");
                        }}
                        className="flex items-center space-x-2"
                      >
                        <div className="flex items-center space-x-2">
                          <RadioGroupItem value="base64" id={optionOneId} />
                          <Label htmlFor={optionOneId}>Base64</Label>
                        </div>
                        <div className="flex items-center space-x-2">
                          <RadioGroupItem value="file" id={optionTwoId} />
                          <Label htmlFor={optionTwoId}>File</Label>
                        </div>
                      </RadioGroup>
                      <FormControl className="mt-2 items-center">
                        {isFile ? (
                          <Input
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) {
                                const reader = new FileReader();
                                reader.onload = (event) => {
                                  const base64String = (event.target?.result as string)?.split(",")[1] || "";
                                  field.onChange(base64String);
                                };
                                reader.readAsDataURL(file);
                              }
                            }}
                            accept=".class"
                            placeholder="请输入"
                            type="file"
                          />
                        ) : (
                          <Textarea {...field} placeholder="请输入" className="h-24" />
                        )}
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
              {watchedParamSource === "requestParam" && (
                <FormField
                  control={form.control}
                  name="requestParamName"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>Request Param Name</FormFieldLabel>
                      <FormControl>
                        <Input placeholder="例如: cmd, data, ..." {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
              {watchedParamSource === "requestHeader" && (
                <FormField
                  control={form.control}
                  name="requestHeaderName"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>Request Header Name</FormFieldLabel>
                      <FormControl>
                        <Input placeholder="例如: cmd, data, ..." {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
            </div>
          )}
          {watchedEchoContent === "command" && (
            <div className="space-y-4 pt-4 border-t mt-4">
              <FormField
                control={form.control}
                name="paramSource"
                render={({ field }) => (
                  <FormFieldItem className="space-y-2">
                    <FormFieldLabel>命令来源</FormFieldLabel>
                    <FormControl>
                      <RadioGroup onValueChange={field.onChange} defaultValue={field.value} className="flex gap-4">
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="builtin" />
                          </FormControl>
                          <FormLabel className="font-normal">内嵌命令</FormLabel>
                        </FormItem>
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="requestHeader" />
                          </FormControl>
                          <FormLabel className="font-normal">通过 Request Header 传递</FormLabel>
                        </FormItem>
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="requestParam" />
                          </FormControl>
                          <FormLabel className="font-normal">通过 Request Param 传递</FormLabel>
                        </FormItem>
                      </RadioGroup>
                    </FormControl>
                    <FormMessage />
                  </FormFieldItem>
                )}
              />
              {watchedParamSource === "builtin" && (
                <FormField
                  control={form.control}
                  name="command"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>执行命令</FormFieldLabel>
                      <FormControl>
                        <Input placeholder="例如: whoami, id, hostname" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
              {watchedParamSource === "requestParam" && (
                <FormField
                  control={form.control}
                  name="requestParamName"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>Request Param Name</FormFieldLabel>
                      <FormControl>
                        <Input placeholder="例如: cmd, data, ..." {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
              {watchedParamSource === "requestHeader" && (
                <FormField
                  control={form.control}
                  name="requestHeaderName"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>Request Header Name</FormFieldLabel>
                      <FormControl>
                        <Input placeholder="例如: cmd, data, ..." {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
            </div>
          )}
        </>
      );
    }

    // --- Sleep Delay ---
    if (watchedEchoMethod === "sleep" && watchedEchoContent) {
      return (
        <div className="space-y-4 pt-4 border-t mt-4">
          {watchedEchoContent === "middleware" && (
            <div className="space-y-4">
              <FormField
                control={form.control}
                name="sleepMiddleware"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>目标中间件</FormFieldLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="选择中间件..." />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="tomcat">Tomcat</SelectItem>
                        <SelectItem value="jetty">Jetty</SelectItem>
                        <SelectItem value="springboot">Spring Boot</SelectItem>
                        <SelectItem value="weblogic">WebLogic</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormFieldItem>
                )}
              />
              <FormField
                control={form.control}
                name="sleepMiddlewareDelay"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>命中延迟时间 (秒)</FormFieldLabel>
                    <FormControl>
                      <Input
                        type="number"
                        placeholder="例如: 5"
                        {...field}
                        onChange={(event) => field.onChange(+event.target.value)}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormFieldItem>
                )}
              />
            </div>
          )}

          {watchedEchoContent === "os" && (
            <div className="space-y-4">
              <FormFieldLabel>操作系统与延迟时间</FormFieldLabel>
              {fields.map((item, index) => (
                <div key={item.id} className="flex items-center gap-2">
                  <Controller
                    control={form.control}
                    name={`sleepOsDelays.${index}.os`}
                    render={({ field }) => (
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="linux">Linux</SelectItem>
                          <SelectItem value="windows">Windows</SelectItem>
                          <SelectItem value="macos">macOS</SelectItem>
                        </SelectContent>
                      </Select>
                    )}
                  />
                  <Controller
                    control={form.control}
                    name={`sleepOsDelays.${index}.delay`}
                    render={({ field }) => (
                      <Input
                        type="number"
                        placeholder="延迟(秒)"
                        {...field}
                        onChange={(event) => field.onChange(+event.target.value)}
                      />
                    )}
                  />
                  <Button type="button" variant="destructive" size="icon" onClick={() => remove(index)}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
              <Button type="button" variant="outline" size="sm" onClick={() => append({ os: "windows", delay: 10 })}>
                添加探测系统
              </Button>
              <FormMessage>{form.formState.errors.sleepOsDelays?.message}</FormMessage>
            </div>
          )}

          {watchedEchoContent === "jdk" && (
            <div className="space-y-4">
              <FormField
                control={form.control}
                name="sleepJdkDetectionType"
                render={({ field }) => (
                  <FormFieldItem className="space-y-2">
                    <FormFieldLabel>JDK 探测类型</FormFieldLabel>
                    <FormControl>
                      <RadioGroup onValueChange={field.onChange} defaultValue={field.value} className="flex gap-4">
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="version" />
                          </FormControl>
                          <FormLabel className="font-normal">按版本 (大于等于)</FormLabel>
                        </FormItem>
                        <FormItem className="flex items-center space-x-2">
                          <FormControl>
                            <RadioGroupItem value="type" />
                          </FormControl>
                          <FormLabel className="font-normal">按类型 (JDK/JRE)</FormLabel>
                        </FormItem>
                      </RadioGroup>
                    </FormControl>
                  </FormFieldItem>
                )}
              />
              {watchedSleepJdkDetectionType === "version" && (
                <FormField
                  control={form.control}
                  name="sleepJdkVersion"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>JDK 版本</FormFieldLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="8">JDK 8</SelectItem>
                          <SelectItem value="11">JDK 11</SelectItem>
                          <SelectItem value="17">JDK 17</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
              {watchedSleepJdkDetectionType === "type" && (
                <FormField
                  control={form.control}
                  name="sleepJdkType"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>目标类型</FormFieldLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="jdk">JDK</SelectItem>
                          <SelectItem value="jre">JRE</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}
              <FormField
                control={form.control}
                name="sleepJdkDelay"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>命中延迟时间 (秒)</FormFieldLabel>
                    <FormControl>
                      <Input
                        type="number"
                        placeholder="例如: 5"
                        {...field}
                        onChange={(event) => field.onChange(+event.target.value)}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormFieldItem>
                )}
              />
            </div>
          )}

          {watchedEchoContent === "bytecode" && (
            <FormField
              control={form.control}
              name="sleepBytecodeSuccessDelay"
              render={({ field }) => (
                <FormFieldItem>
                  <FormFieldLabel>执行成功延迟时间 (秒)</FormFieldLabel>
                  <FormControl>
                    <Input
                      type="number"
                      placeholder="例如: 8"
                      {...field}
                      onChange={(event) => field.onChange(+event.target.value)}
                    />
                  </FormControl>
                  <FormMessage />
                </FormFieldItem>
              )}
            />
          )}
        </div>
      );
    }

    return null;
  };

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      <Card>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)}>
            <CardContent className="mt-2">
              <FormField
                control={form.control}
                name="echoMethod"
                render={({ field }) => (
                  <FormFieldItem>
                    <FormFieldLabel>回显方式</FormFieldLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="header">Response Header</SelectItem>
                        <SelectItem value="body">Response Body</SelectItem>
                        <SelectItem value="dnslog">DNSLog</SelectItem>
                        <SelectItem value="httplog">HTTPLog</SelectItem>
                        <SelectItem value="sleep">Sleep 延迟探测</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormFieldItem>
                )}
              />

              {/* --- 根据回显方式出现的特定字段 --- */}
              {(watchedEchoMethod === "header" || watchedEchoMethod === "body") && (
                <FormField
                  control={form.control}
                  name="middlewareType"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>中间件类型</FormFieldLabel>
                      <FormDescription>不同的中间件获取 Request/Response 的方式不同。</FormDescription>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="选择中间件..." />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="tomcat">Tomcat</SelectItem>
                          <SelectItem value="jetty">Jetty</SelectItem>
                          <SelectItem value="springboot">Spring Boot</SelectItem>
                          <SelectItem value="weblogic">WebLogic</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}

              {watchedEchoMethod === "header" && (
                <FormField
                  control={form.control}
                  name="headerName"
                  render={({ field }) => (
                    <FormFieldItem>
                      <FormFieldLabel>Response Header Name</FormFieldLabel>
                      <FormControl>
                        <Input placeholder="例如: X-Echo-Result" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormFieldItem>
                  )}
                />
              )}

              {(watchedEchoMethod === "dnslog" || watchedEchoMethod === "httplog") && (
                <>
                  <Alert className="mt-2 mb-2">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>注意</AlertTitle>
                    <AlertDescription>此方式要求目标服务器能够访问外网 (出网)。</AlertDescription>
                  </Alert>
                  <FormField
                    control={form.control}
                    name="logAddress"
                    render={({ field }) => (
                      <FormFieldItem>
                        <FormFieldLabel>{watchedEchoMethod === "dnslog" ? "DNSLog" : "HTTPLog"} 地址</FormFieldLabel>
                        <FormControl>
                          <Input placeholder="例如: abcde.dnslog.cn" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormFieldItem>
                    )}
                  />
                </>
              )}
              {watchedEchoMethod && renderContentOptions()}
              {renderDynamicFields()}
            </CardContent>
            <CardFooter className="mt-2">
              <Button type="submit">生成载荷</Button>
            </CardFooter>
          </form>
        </Form>
      </Card>
    </div>
  );
}
