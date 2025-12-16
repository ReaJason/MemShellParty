import { InfoIcon, ServerIcon } from "lucide-react";
import { useCallback, useEffect, useMemo } from "react";
import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Field,
  FieldContent,
  FieldError,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { ServerConfig } from "@/types/memshell";
import type { ProbeShellFormSchema } from "@/types/schema";

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

  const isBodyMethod = watchedProbeMethod === "ResponseBody";
  const isCommandBody = watchedProbeContent === "Command";
  const needParam =
    isCommandBody ||
    watchedProbeContent === "Bytecode" ||
    watchedProbeContent === "ScriptEngine";
  const isSleepMethod = watchedProbeMethod === "Sleep";
  const isServerContent = watchedProbeContent === "Server";

  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <ServerIcon className="h-5 w-5" />
          <span>{t("mainConfig.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <Controller
          control={form.control}
          name="probeMethod"
          render={({ field, fieldState }) => (
            <Field className="gap-1">
              <FieldLabel>{t("probeshell:probeMethod")}</FieldLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <div>
                  <SelectTrigger>
                    <SelectValue
                      data-placeholder={t("common:placeholders.select")}
                    />
                  </SelectTrigger>
                </div>
                <SelectContent>
                  {PROBE_METHOD_OPTIONS.map(({ value, label }) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {fieldState.error && <FieldError errors={[fieldState.error]} />}
            </Field>
          )}
        />
        {watchedProbeMethod === "ResponseBody" && (
          <Controller
            control={form.control}
            name="server"
            render={({ field, fieldState }) => (
              <Field
                className="gap-1"
                orientation="vertical"
                data-invalid={fieldState.invalid}
              >
                <FieldContent>
                  <FieldLabel htmlFor="server">{t("server")}</FieldLabel>
                  <Select
                    onValueChange={field.onChange}
                    defaultValue={field.value}
                  >
                    <SelectTrigger
                      id="server"
                      aria-invalid={fieldState.invalid}
                    >
                      <SelectValue
                        data-placeholder={t("placeholders.select")}
                      />
                    </SelectTrigger>
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
                  {fieldState.error && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </FieldContent>
              </Field>
            )}
          />
        )}
        {watchedProbeMethod === "DNSLog" && (
          <Controller
            control={form.control}
            name="host"
            render={({ field, fieldState }) => (
              <Field
                className="gap-1"
                orientation="vertical"
                data-invalid={fieldState.invalid}
              >
                <FieldLabel>{t("probeshell:dnslog.host")}</FieldLabel>
                <Input placeholder={t("placeholders.input")} {...field} />
                {fieldState.error && <FieldError errors={[fieldState.error]} />}
              </Field>
            )}
          />
        )}
        {watchedProbeMethod && (
          <Controller
            control={form.control}
            name="probeContent"
            render={({ field, fieldState }) => (
              <Field orientation="vertical" data-invalid={fieldState.invalid}>
                <FieldContent>
                  <FieldLabel htmlFor="probeContent">
                    {t("probeshell:probeContent")}
                  </FieldLabel>
                  <Select
                    onValueChange={field.onChange}
                    value={field.value || ""}
                  >
                    <SelectTrigger
                      aria-invalid={fieldState.invalid}
                      id="probeContent"
                    >
                      <SelectValue
                        data-placeholder={t("common:placeholders.select")}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      {filteredOptions.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {t(`probeshell:probeContent.${opt.label}`)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {fieldState.error && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </FieldContent>
              </Field>
            )}
          />
        )}
        <div className="flex gap-4 mt-4 flex-col lg:grid lg:grid-cols-2 2xl:grid 2xl:grid-cols-3">
          <Controller
            control={form.control}
            name="debug"
            render={({ field }) => (
              <div className="flex items-center gap-2">
                <Switch
                  id="debug"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
                <Label htmlFor="debug">{t("common:debug")}</Label>
                <Tooltip>
                  <TooltipTrigger>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:debug.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            )}
          />
          <Controller
            control={form.control}
            name="byPassJavaModule"
            render={({ field }) => (
              <div className="flex items-center gap-2">
                <Switch
                  id="bypass"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
                <Label htmlFor="bypass">{t("common:byPassJavaModule")}</Label>
                <Tooltip>
                  <TooltipTrigger>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:byPassJavaModule.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            )}
          />
          <Controller
            control={form.control}
            name="lambdaSuffix"
            render={({ field }) => (
              <div className="flex items-center gap-2">
                <Switch
                  id="lambdaSuffix"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
                <Label htmlFor="lambdaSuffix">{t("common:lambdaSuffix")}</Label>
                <Tooltip>
                  <TooltipTrigger>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:lambdaSuffix.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            )}
          />
          <Controller
            control={form.control}
            name="shrink"
            render={({ field }) => (
              <div className="flex items-center gap-2">
                <Switch
                  id="shrink"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
                <Label htmlFor="shrink">{t("common:shrink")}</Label>
                <Tooltip>
                  <TooltipTrigger>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:shrink.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            )}
          />
          <Controller
            control={form.control}
            name="staticInitialize"
            render={({ field }) => (
              <div className="flex items-center gap-2">
                <Switch
                  id="staticInitialize"
                  checked={field.value}
                  onCheckedChange={field.onChange}
                />
                <Label htmlFor="staticInitialize">
                  {t("common:staticInitialize")}
                </Label>
                <Tooltip>
                  <TooltipTrigger>
                    <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{t("common:staticInitialize.description")}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            )}
          />
        </div>
        {isBodyMethod && needParam && (
          <div className="space-y-2 pt-4 border-t mt-4">
            <Controller
              control={form.control}
              name="reqParamName"
              render={({ field, fieldState }) => (
                <Field className="gap-1">
                  <div className="flex items-center gap-1">
                    <FieldLabel>
                      {t("common:paramName")} {t("common:optional")}
                    </FieldLabel>
                    <Tooltip>
                      <TooltipTrigger>
                        <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>{t("common:paramName.description")}</p>
                      </TooltipContent>
                    </Tooltip>
                  </div>
                  <Input placeholder={t("placeholders.input")} {...field} />
                  {fieldState.error && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </Field>
              )}
            />
          </div>
        )}
        {isBodyMethod && isCommandBody && (
          <Controller
            control={form.control}
            name="commandTemplate"
            render={({ field }) => (
              <Field className="gap-1">
                <FieldLabel>
                  {t("common:commandTemplate")} {t("common:optional")}
                </FieldLabel>
                <Input
                  {...field}
                  placeholder={t("common:commandTemplate.placeholder")}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {t("common:commandTemplate.description")}
                </p>
              </Field>
            )}
          />
        )}
        {isSleepMethod && isServerContent && (
          <div className="space-y-2 pt-4 border-t mt-4">
            <Controller
              control={form.control}
              name="sleepServer"
              render={({ field, fieldState }) => (
                <Field
                  className="gap-1"
                  orientation="vertical"
                  data-invalid={fieldState.invalid}
                >
                  <FieldContent>
                    <FieldLabel htmlFor="sleepServer">
                      {t("probeshell:sleepServer")}
                    </FieldLabel>
                    <Select
                      onValueChange={field.onChange}
                      value={field.value || ""}
                    >
                      <SelectTrigger
                        aria-invalid={fieldState.invalid}
                        id="sleepServer"
                      >
                        <SelectValue
                          data-placeholder={t("placeholders.select")}
                        />
                      </SelectTrigger>
                      <SelectContent>
                        {MIDDLEWARE_OPTIONS.map(({ value, label }) => (
                          <SelectItem key={value} value={value}>
                            {label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {fieldState.error && (
                      <FieldError errors={[fieldState.error]} />
                    )}
                  </FieldContent>
                </Field>
              )}
            />
            <Controller
              control={form.control}
              name="seconds"
              render={({ field, fieldState }) => (
                <Field
                  className="gap-1"
                  orientation="vertical"
                  data-invalid={fieldState.invalid}
                >
                  <FieldLabel>{t("probeshell:sleepSeconds")}</FieldLabel>
                  <Input
                    type="number"
                    placeholder={t("placeholders.input")}
                    {...field}
                    onChange={(event) => field.onChange(+event.target.value)}
                  />
                  {fieldState.error && (
                    <FieldError errors={[fieldState.error]} />
                  )}
                </Field>
              )}
            />
          </div>
        )}
        <Separator />
        <Controller
          control={form.control}
          name="shellClassName"
          render={({ field }) => (
            <Field className="gap-1">
              <FieldLabel htmlFor="shellClassName">
                {t("probeshell:shellClassName")} {t("optional")}
              </FieldLabel>
              <Input
                id="shellClassName"
                {...field}
                placeholder={t("placeholders.input")}
              />
            </Field>
          )}
        />
      </CardContent>
    </Card>
  );
}
