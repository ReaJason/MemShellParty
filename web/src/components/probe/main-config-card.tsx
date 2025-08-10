import { ServerIcon } from "lucide-react";
import { useCallback, useEffect, useMemo } from "react";
import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  FormControl,
  FormField,
  FormFieldItem,
  FormFieldLabel,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { ProbeFormSchema } from "@/types/schema";
import type { ServerConfig } from "@/types/shell";
import { Separator } from "../ui/separator";

// 常量提取到组件外部
const PROBE_OPTIONS = [
  { value: "Server" as const, label: "中间件类型" },
  { value: "JDK" as const, label: "JDK 信息" },
  { value: "Command" as const, label: "命令执行" },
  { value: "Bytecode" as const, label: "自定义字节码执行" },
] as const;

const MIDDLEWARE_OPTIONS = [
  { value: "Tomcat", label: "Tomcat" },
  { value: "Jetty", label: "Jetty" },
  { value: "Undertow", label: "Undertow" },
  { value: "Resin", label: "Resin" },
  { value: "JBoss", label: "JBoss" },
  { value: "GlassFish", label: "GlassFish" },
  { value: "BES", label: "BES" },
  { value: "TongWeb", label: "TongWeb" },
  { value: "InforSuite", label: "InforSuite" },
  { value: "Apusic", label: "Apusic" },
  { value: "SpringWebFlux", label: "SpringWebFlux" },
  { value: "WebLogic", label: "WebLogic" },
  { value: "WebSphere", label: "WebSphere" },
] as const;

const PROBE_METHOD_OPTIONS = [
  { value: "Sleep", label: "Sleep 延迟探测" },
  { value: "DNSLog", label: "DNSLog" },
  { value: "ResponseBody", label: "ResponseBody" },
] as const;

// 默认值配置
const DEFAULT_FORM_VALUES = {
  reqParamName: "payload",
  reqHeaderName: "X-PAYLOAD",
  sleepServer: "Tomcat",
  seconds: 5,
} as const;

interface MainConfigCardProps {
  readonly form: UseFormReturn<ProbeFormSchema>;
  readonly servers?: ServerConfig;
}

export default function MainConfigCard({ form, servers }: MainConfigCardProps) {
  const { t } = useTranslation();
  const watchedProbeMethod = form.watch("probeMethod");
  const watchedProbeContent = form.watch("probeContent");

  const filteredOptions = useMemo(() => {
    const filterMap = {
      ResponseBody: ["Command", "Bytecode"],
      DNSLog: ["JDK", "Server"],
      Sleep: ["Server"],
    } as const;

    const allowedValues = filterMap[watchedProbeMethod as keyof typeof filterMap];
    
    if (!allowedValues) return PROBE_OPTIONS;
    
    return PROBE_OPTIONS.filter(opt => 
      allowedValues.includes(opt.value as never)
    );
  }, [watchedProbeMethod]);

  const resetFormValues = useCallback(() => {
    if (filteredOptions.length === 0) return;

    const currentValues = form.getValues();
    form.reset({
      ...currentValues,
      probeMethod: watchedProbeMethod,
      probeContent: filteredOptions[0].value,
      ...DEFAULT_FORM_VALUES,
    });
  }, [form, watchedProbeMethod, filteredOptions]);

  useEffect(() => {
    resetFormValues();
  }, [resetFormValues]);

  const ContentOptionsSelect = useMemo(() => (
    <FormField
      control={form.control}
      name="probeContent"
      render={({ field }) => (
        <FormFieldItem>
          <FormFieldLabel>探测内容</FormFieldLabel>
          <Select onValueChange={field.onChange} value={field.value || ""}>
            <FormControl>
              <SelectTrigger>
                <SelectValue placeholder="请选择要探测的内容..." />
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
  ), [form.control, filteredOptions]);

  const RequestParamField = useMemo(() => (
    <div className="space-y-4 pt-4 border-t mt-4">
      <FormField
        control={form.control}
        name="reqParamName"
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
    </div>
  ), [form.control]);

  const SleepFields = useMemo(() => (
    <div className="space-y-4 pt-4 border-t mt-4">
      <div className="space-y-4">
        <FormField
          control={form.control}
          name="sleepServer"
          render={({ field }) => (
            <FormFieldItem>
              <FormFieldLabel>探测中间件</FormFieldLabel>
              <Select onValueChange={field.onChange} value={field.value || ""}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="选择中间件..." />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {MIDDLEWARE_OPTIONS.map(({ value, label }) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormFieldItem>
          )}
        />
        <FormField
          control={form.control}
          name="seconds"
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
    </div>
  ), [form.control]);

  const renderDynamicFields = useCallback(() => {
    const isBodyMethod = watchedProbeMethod === "ResponseBody";
    const isCommandOrBytecode = watchedProbeContent === "Command" || watchedProbeContent === "Bytecode";
    const isSleepMethod = watchedProbeMethod === "Sleep";
    const isServerContent = watchedProbeContent === "Server";

    if (isBodyMethod && isCommandOrBytecode) {
      return RequestParamField;
    }

    if (isSleepMethod && isServerContent) {
      return SleepFields;
    }

    return null;
  }, [watchedProbeMethod, watchedProbeContent, RequestParamField, SleepFields]);


  const DNSLogSection = useMemo(() => (
      <FormField
        control={form.control}
        name="host"
        render={({ field }) => (
          <FormFieldItem>
            <FormFieldLabel>DNSLog 地址</FormFieldLabel>
            <FormControl>
              <Input placeholder="例如: abcde.DNSLog.cn" {...field} />
            </FormControl>
            <FormMessage />
          </FormFieldItem>
        )}
      />
  ), [form.control]);

  const MiddlewareSelect = useMemo(() => (
    <FormField
      control={form.control}
      name="server"
      render={({ field }) => (
        <FormFieldItem>
          <FormFieldLabel>中间件类型</FormFieldLabel>
          <Select onValueChange={field.onChange} defaultValue={field.value}>
            <FormControl>
              <SelectTrigger>
                <SelectValue placeholder="选择中间件..." />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              {Object.keys(servers ?? {}).map((server: string) => (
                <SelectItem key={server} value={server}>
                  {server}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <FormMessage />
        </FormFieldItem>
      )}
    />
  ), [form.control, servers]);

  const SwitchGroup = useMemo(() => (
    <div className="flex gap-4 mt-4 flex-col sm:flex-row">
      <FormField
        control={form.control}
        name="debug"
        render={({ field }) => (
          <FormItem className="flex items-center space-x-2 space-y-0">
            <FormControl>
              <Switch id="debug" checked={field.value} onCheckedChange={field.onChange} />
            </FormControl>
            <FormLabel htmlFor="debug">{t("mainConfig.debug")}</FormLabel>
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="byPassJavaModule"
        render={({ field }) => (
          <FormItem className="flex items-center space-x-2 space-y-0">
            <FormControl>
              <Switch id="bypass" checked={field.value} onCheckedChange={field.onChange} />
            </FormControl>
            <Label htmlFor="bypass">{t("mainConfig.byPassJavaModule")}</Label>
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="shrink"
        render={({ field }) => (
          <FormItem className="flex items-center space-x-2 space-y-0">
            <FormControl>
              <Switch id="shrink" checked={field.value} onCheckedChange={field.onChange} />
            </FormControl>
            <Label htmlFor="shrink">{t("mainConfig.shrink")}</Label>
          </FormItem>
        )}
      />
    </div>
  ), [form.control, t]);

  return (
    <FormProvider {...form}>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-md flex items-center gap-2">
            <ServerIcon className="h-5 w-5" />
            <span>{t("configs.main-config")}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <FormField
            control={form.control}
            name="probeMethod"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel>探测方式</FormFieldLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {PROBE_METHOD_OPTIONS.map(({ value, label }) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormFieldItem>
            )}
          />

          {watchedProbeMethod === "ResponseBody" && MiddlewareSelect}
          {watchedProbeMethod === "DNSLog" && DNSLogSection}
          {watchedProbeMethod && ContentOptionsSelect}
          {SwitchGroup}
          {renderDynamicFields()}
          <Separator />
          <FormField
            control={form.control}
            name="shellClassName"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel htmlFor="shellClassName">
                  {t("mainConfig.shellClassName")} {t("optional")}
                </FormFieldLabel>
                <Input id="shellClassName" {...field} placeholder={t("placeholders.input")} />
              </FormFieldItem>
            )}
          />
        </CardContent>
      </Card>
    </FormProvider>
  );
}