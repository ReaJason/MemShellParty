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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { ServerConfig } from "@/types/memshell";
import type { ProbeShellFormSchema } from "@/types/schema";
import { Separator } from "../ui/separator";

const PROBE_OPTIONS = [
  { value: "Server" as const, label: "server" },
  { value: "JDK" as const, label: "jdk" },
  { value: "Command" as const, label: "command" },
  { value: "Bytecode" as const, label: "bytecode" },
  { value: "ScriptEngine" as const, label: "script" },
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
  { value: "Sleep", label: "Sleep" },
  { value: "DNSLog", label: "DNSLog" },
  { value: "ResponseBody", label: "ResponseBody" },
] as const;

const DEFAULT_FORM_VALUES = {
  reqParamName: "payload",
  sleepServer: "Tomcat",
  seconds: 5,
} as const;

interface MainConfigCardProps {
  readonly form: UseFormReturn<ProbeShellFormSchema>;
  readonly servers?: ServerConfig;
}

export default function MainConfigCard({ form, servers }: MainConfigCardProps) {
  const { t } = useTranslation(["common", "probeshell"]);
  const watchedProbeMethod = form.watch("probeMethod");
  const watchedProbeContent = form.watch("probeContent");

  const filteredOptions = useMemo(() => {
    const filterMap = {
      ResponseBody: ["Command", "Bytecode", "ScriptEngine"],
      DNSLog: ["JDK", "Server"],
      Sleep: ["Server"],
    } as const;

    const allowedValues =
      filterMap[watchedProbeMethod as keyof typeof filterMap];

    if (!allowedValues) return PROBE_OPTIONS;

    return PROBE_OPTIONS.filter((opt) =>
      allowedValues.includes(opt.value as never),
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

  const ContentOptionsSelect = useMemo(
    () => (
      <FormField
        control={form.control}
        name="probeContent"
        render={({ field }) => (
          <FormFieldItem>
            <FormFieldLabel>{t("probeshell:probeContent")}</FormFieldLabel>
            <Select onValueChange={field.onChange} value={field.value || ""}>
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder={t("common:placeholders.select")} />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {filteredOptions.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    {t(`probeshell:probeContent.${opt.label}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormMessage />
          </FormFieldItem>
        )}
      />
    ),
    [form.control, filteredOptions, t],
  );

  const RequestParamField = useMemo(
    () => (
      <div className="space-y-2 pt-4 border-t mt-4">
        <FormField
          control={form.control}
          name="reqParamName"
          render={({ field }) => (
            <FormFieldItem>
              <FormFieldLabel>{t("common:paramName")}</FormFieldLabel>
              <FormControl>
                <Input placeholder={t("placeholders.input")} {...field} />
              </FormControl>
              <FormMessage />
            </FormFieldItem>
          )}
        />
      </div>
    ),
    [form.control, t],
  );

  const SleepFields = useMemo(
    () => (
      <div className="space-y-2 pt-4 border-t mt-4">
        <FormField
          control={form.control}
          name="sleepServer"
          render={({ field }) => (
            <FormFieldItem>
              <FormFieldLabel>{t("probeshell:sleepServer")}</FormFieldLabel>
              <Select onValueChange={field.onChange} value={field.value || ""}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder={t("placeholders.select")} />
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
              <FormFieldLabel>{t("probeshell:sleepSeconds")}</FormFieldLabel>
              <FormControl>
                <Input
                  type="number"
                  placeholder={t("placeholders.input")}
                  {...field}
                  onChange={(event) => field.onChange(+event.target.value)}
                />
              </FormControl>
              <FormMessage />
            </FormFieldItem>
          )}
        />
      </div>
    ),
    [form.control, t],
  );

  const renderDynamicFields = useCallback(() => {
    const isBodyMethod = watchedProbeMethod === "ResponseBody";
    const needParam =
      watchedProbeContent === "Command" ||
      watchedProbeContent === "Bytecode" ||
      watchedProbeContent === "ScriptEngine";
    const isSleepMethod = watchedProbeMethod === "Sleep";
    const isServerContent = watchedProbeContent === "Server";

    if (isBodyMethod && needParam) {
      return RequestParamField;
    }

    if (isSleepMethod && isServerContent) {
      return SleepFields;
    }

    return null;
  }, [watchedProbeMethod, watchedProbeContent, RequestParamField, SleepFields]);

  const DNSLogSection = useMemo(
    () => (
      <FormField
        control={form.control}
        name="host"
        render={({ field }) => (
          <FormFieldItem>
            <FormFieldLabel>{t("probeshell:dnslog.host")}</FormFieldLabel>
            <FormControl>
              <Input placeholder={t("placeholders.input")} {...field} />
            </FormControl>
            <FormMessage />
          </FormFieldItem>
        )}
      />
    ),
    [form.control, t],
  );

  const MiddlewareSelect = useMemo(
    () => (
      <FormField
        control={form.control}
        name="server"
        render={({ field }) => (
          <FormFieldItem>
            <FormFieldLabel>{t("server")}</FormFieldLabel>
            <Select onValueChange={field.onChange} defaultValue={field.value}>
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder={t("placeholders.select")} />
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
    ),
    [form.control, servers, t],
  );

  const SwitchGroup = useMemo(
    () => (
      <div className="flex gap-4 mt-4 flex-col sm:flex-row">
        <FormField
          control={form.control}
          name="debug"
          render={({ field }) => (
            <FormItem className="flex items-center space-x-2 space-y-0">
              <FormControl>
                <Switch
                  id="debug"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              </FormControl>
              <FormLabel htmlFor="debug">{t("debug")}</FormLabel>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="byPassJavaModule"
          render={({ field }) => (
            <FormItem className="flex items-center space-x-2 space-y-0">
              <FormControl>
                <Switch
                  id="bypass"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              </FormControl>
              <Label htmlFor="bypass">{t("byPassJavaModule")}</Label>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="shrink"
          render={({ field }) => (
            <FormItem className="flex items-center space-x-2 space-y-0">
              <FormControl>
                <Switch
                  id="shrink"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              </FormControl>
              <Label htmlFor="shrink">{t("shrink")}</Label>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="staticInitialize"
          render={({ field }) => (
            <FormItem className="flex items-center space-x-2 space-y-0">
              <FormControl>
                <Switch
                  id="staticInitialize"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              </FormControl>
              <Label htmlFor="staticInitialize">
                {t("common:staticInitialize")}
              </Label>
            </FormItem>
          )}
        />
      </div>
    ),
    [form.control, t],
  );

  return (
    <FormProvider {...form}>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-md flex items-center gap-2">
            <ServerIcon className="h-5 w-5" />
            <span>{t("mainConfig.title")}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <FormField
            control={form.control}
            name="probeMethod"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel>{t("probeshell:probeMethod")}</FormFieldLabel>
                <Select
                  onValueChange={field.onChange}
                  defaultValue={field.value}
                >
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
                  {t("probeshell:shellClassName")} {t("optional")}
                </FormFieldLabel>
                <Input
                  id="shellClassName"
                  {...field}
                  placeholder={t("placeholders.input")}
                />
              </FormFieldItem>
            )}
          />
        </CardContent>
      </Card>
    </FormProvider>
  );
}
