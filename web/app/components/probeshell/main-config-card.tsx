import { InfoIcon, ServerIcon } from "lucide-react";
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
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
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
  { value: "ResponseBody", label: "ResponseBody" },
  { value: "DNSLog", label: "DNSLog" },
  { value: "Sleep", label: "Sleep" },
] as const;

const DEFAULT_FORM_VALUES = {
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
              <div className="flex items-center gap-1">
                <FormFieldLabel>
                  {t("common:paramName")} {t("common:optional")}
                </FormFieldLabel>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:paramName.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
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

  const CommandTemplateField = useMemo(
    () => (
      <div className="space-y-2">
        <FormField
          control={form.control}
          name="commandTemplate"
          render={({ field }) => (
            <FormFieldItem>
              <FormFieldLabel>
                {t("common:commandTemplate")} {t("common:optional")}
              </FormFieldLabel>
              <FormControl>
                <Input
                  {...field}
                  placeholder={t("common:commandTemplate.placeholder")}
                />
              </FormControl>
              <p className="text-xs text-muted-foreground mt-1">
                {t("common:commandTemplate.description")}
              </p>
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
                {Object.keys(servers ?? {})
                  .filter((s) => s !== "SpringWebFlux" && s !== "XXLJOB")
                  .map((server: string) => (
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
      <div className="flex gap-4 mt-4 flex-col lg:grid lg:grid-cols-2 2xl:grid 2xl:grid-cols-3">
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
              <div className="flex items-center gap-1">
                <FormLabel htmlFor="debug">{t("debug")}</FormLabel>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:debug.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
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
              <div className="flex items-center gap-1">
                <Label htmlFor="bypass">{t("byPassJavaModule")}</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:byPassJavaModule.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="lambdaSuffix"
          render={({ field }) => (
            <FormItem className="flex items-center space-x-2  space-y-0">
              <FormControl>
                <Switch
                  id="lambdaSuffix"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
              </FormControl>
              <div className="flex items-center gap-1">
                <Label htmlFor="lambdaSuffix">{t("common:lambdaSuffix")}</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:lambdaSuffix.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
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
              <div className="flex items-center gap-1">
                <Label htmlFor="shrink">{t("shrink")}</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:shrink.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
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
              <div className="flex items-center gap-1">
                <Label htmlFor="staticInitialize">
                  {t("common:staticInitialize")}
                </Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:staticInitialize.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            </FormItem>
          )}
        />
      </div>
    ),
    [form.control, t],
  );

  const isBodyMethod = watchedProbeMethod === "ResponseBody";
  const isCommandBody = watchedProbeContent === "Command";
  const needParam =
    isCommandBody ||
    watchedProbeContent === "Bytecode" ||
    watchedProbeContent === "ScriptEngine";
  const isSleepMethod = watchedProbeMethod === "Sleep";
  const isServerContent = watchedProbeContent === "Server";

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
          {isBodyMethod && needParam && RequestParamField}
          {isBodyMethod && isCommandBody && CommandTemplateField}
          {isSleepMethod && isServerContent && SleepFields}
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
