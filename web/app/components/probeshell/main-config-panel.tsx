import type { PackerConfig } from "@/types/memshell";
import type { ProbeShellFormSchema } from "@/types/schema";

import { InfoIcon, PackageIcon, ServerIcon, Shuffle } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { BytecodeOptions } from "@/components/bytecode-config-card";
import { Button } from "@/components/ui/button";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

import { ProbeClassFormField } from "./classname-field";
import { PackageConfigFields } from "./package-config-fields";

// Hoisted static JSX to avoid recreation on each render (rendering-hoist-jsx)
const infoIcon = <InfoIcon className="h-3.5 w-3.5 cursor-help text-muted-foreground" />;
const requiredMark = (
  <span aria-hidden="true" className="ml-0.5 text-destructive">
    *
  </span>
);

const PROBE_OPTIONS = [
  { value: "Server" as const, label: "server" },
  { value: "JDK" as const, label: "jdk" },
  { value: "Command" as const, label: "command" },
  { value: "Bytecode" as const, label: "bytecode" },
  { value: "ScriptEngine" as const, label: "script" },
  { value: "Filter" as const, label: "filter" },
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
  { value: "SpringWebMvc", label: "SpringWebMvc" },
  { value: "SpringWebFlux", label: "SpringWebFlux" },
  { value: "WebLogic", label: "WebLogic" },
  { value: "WebSphere", label: "WebSphere" },
] as const;

const PROBE_METHOD_OPTIONS = [
  { value: "ResponseBody", label: "ResponseBody" },
  { value: "ResponseHeader", label: "ResponseHeader" },
  { value: "DNSLog", label: "DNSLog" },
  { value: "Sleep", label: "Sleep" },
] as const;

const DEFAULT_FORM_VALUES = {
  sleepServer: "Tomcat",
  seconds: 5,
} as const;

interface MainConfigPanelProps {
  readonly form: UseFormReturn<ProbeShellFormSchema>;
  readonly responseServers?: string[];
  readonly serversError?: Error | null;
  readonly isServersRetrying?: boolean;
  readonly onRetryServers?: () => void;
  readonly packerConfig?: PackerConfig;
  readonly packerConfigError?: Error | null;
  readonly isPackerRetrying?: boolean;
  readonly onRetryPacker?: () => void;
}

export default function MainConfigPanel({
  form,
  responseServers,
  serversError,
  isServersRetrying = false,
  onRetryServers,
  packerConfig,
  packerConfigError = null,
  isPackerRetrying = false,
  onRetryPacker = () => {},
}: MainConfigPanelProps) {
  const { t } = useTranslation(["common", "probeshell"]);
  const watchedProbeMethod = form.watch("probeMethod");
  const watchedProbeContent = form.watch("probeContent");
  const watchedServer = form.watch("server");

  const filteredOptions = useMemo(() => {
    const filterMap = {
      ResponseBody: ["Server", "Command", "Bytecode", "ScriptEngine", "Filter"],
      ResponseHeader: ["Server", "Command", "Bytecode", "ScriptEngine", "Filter"],
      DNSLog: ["JDK", "Server"],
      Sleep: ["Server"],
    } as const;

    const allowedValues = filterMap[watchedProbeMethod as keyof typeof filterMap];

    if (!allowedValues) return PROBE_OPTIONS;

    return PROBE_OPTIONS.filter((opt) => allowedValues.includes(opt.value as never));
  }, [watchedProbeMethod]);

  const resetFormValues = useCallback(() => {
    if (filteredOptions.length === 0) return;

    const currentValues = form.getValues();
    form.reset({
      ...currentValues,
      probeMethod: watchedProbeMethod,
      probeContent: filteredOptions[0].value,
      // ResponseBody / ResponseHeader 的服务类型默认 Unknown
      server: "Unknown",
      ...DEFAULT_FORM_VALUES,
    });
  }, [form, watchedProbeMethod, filteredOptions]);

  useEffect(() => {
    resetFormValues();
  }, [resetFormValues]);

  const isResponseMethod =
    watchedProbeMethod === "ResponseBody" || watchedProbeMethod === "ResponseHeader";
  const isResponseHeader = watchedProbeMethod === "ResponseHeader";
  const isCommandBody = watchedProbeContent === "Command";
  const isFilter = watchedProbeContent === "Filter";
  const isServerContent = watchedProbeContent === "Server";
  const isSleepMethod = watchedProbeMethod === "Sleep";
  const needParam =
    !isFilter &&
    (isCommandBody ||
      watchedProbeContent === "Bytecode" ||
      watchedProbeContent === "ScriptEngine" ||
      // Unknown 中间件靠 BFS 遍历字段图定位请求，必须用触发参数认出当前请求
      (isServerContent && watchedServer === "Unknown"));
  const showParamSection = isResponseMethod && (needParam || isResponseHeader);
  const showCommandTemplate = isResponseMethod && isCommandBody;

  // 参数默认随机：与内存马工具参数一致，开启时隐藏并清空参数字段，由后端生成。
  const [randomParams, setRandomParams] = useState(
    () =>
      !(
        form.getValues("reqParamName")?.trim() ||
        form.getValues("commandTemplate")?.trim() ||
        form.getValues("respHeaderName")?.trim()
      ),
  );
  const savedParamsRef = useRef({ reqParamName: "", commandTemplate: "", respHeaderName: "" });

  // 切换探测方法/内容后回到随机参数，避免把上一项内容的参数带到新内容上。
  useEffect(() => {
    setRandomParams(true);
    form.setValue("reqParamName", "");
    form.setValue("commandTemplate", "");
    form.setValue("respHeaderName", "");
  }, [watchedProbeMethod, watchedProbeContent, form]);

  const handleRandomParamsChange = (checked: boolean) => {
    setRandomParams(checked);
    if (checked) {
      savedParamsRef.current = {
        reqParamName: form.getValues("reqParamName") ?? "",
        commandTemplate: form.getValues("commandTemplate") ?? "",
        respHeaderName: form.getValues("respHeaderName") ?? "",
      };
      form.setValue("reqParamName", "");
      form.setValue("commandTemplate", "");
      form.setValue("respHeaderName", "");
      return;
    }
    form.setValue("reqParamName", savedParamsRef.current.reqParamName);
    form.setValue("commandTemplate", savedParamsRef.current.commandTemplate);
    form.setValue("respHeaderName", savedParamsRef.current.respHeaderName);
  };

  const renderProbeMethod = () => (
    <Controller
      control={form.control}
      name="probeMethod"
      render={({ field, fieldState }) => (
        <Field className="gap-1" data-invalid={fieldState.invalid}>
          <FieldLabel>
            {t("probeshell:probeMethod")}
            {requiredMark}
          </FieldLabel>
          <Select onValueChange={field.onChange} value={field.value}>
            <SelectTrigger aria-invalid={fieldState.invalid}>
              <SelectValue data-placeholder={t("common:placeholders.select")} />
            </SelectTrigger>
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
  );

  const renderProbeContent = () => (
    <Controller
      control={form.control}
      name="probeContent"
      render={({ field, fieldState }) => (
        <Field className="gap-1" orientation="vertical" data-invalid={fieldState.invalid}>
          <FieldLabel htmlFor="probeContent">
            {t("probeshell:probeContent")}
            {requiredMark}
          </FieldLabel>
          <Select onValueChange={field.onChange} value={field.value || ""}>
            <SelectTrigger aria-invalid={fieldState.invalid} id="probeContent">
              <SelectValue data-placeholder={t("common:placeholders.select")} />
            </SelectTrigger>
            <SelectContent>
              {filteredOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {t(`probeshell:probeContent.${opt.label}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {fieldState.error && <FieldError errors={[fieldState.error]} />}
        </Field>
      )}
    />
  );

  const renderServer = () => (
    <Controller
      control={form.control}
      name="server"
      render={({ field, fieldState }) => (
        <Field className="gap-1" orientation="vertical" data-invalid={fieldState.invalid}>
          <FieldLabel htmlFor="server">
            {t("server")}
            {requiredMark}
          </FieldLabel>
          <Select onValueChange={field.onChange} value={field.value}>
            <SelectTrigger id="server" aria-invalid={fieldState.invalid}>
              <SelectValue data-placeholder={t("placeholders.select")} />
            </SelectTrigger>
            <SelectContent>
              {responseServers?.map((server) => (
                <SelectItem key={server} value={server}>
                  {server}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {fieldState.error && <FieldError errors={[fieldState.error]} />}
          {serversError && (
            <div className="flex flex-wrap items-center gap-x-1 text-xs text-destructive">
              <span>{t("common:configLoadError.title")}</span>
              <Button
                type="button"
                variant="link"
                size="xs"
                className="h-auto px-0 text-xs"
                disabled={isServersRetrying}
                onClick={onRetryServers}
              >
                {isServersRetrying
                  ? t("common:configLoadError.retrying")
                  : t("common:configLoadError.retry")}
              </Button>
            </div>
          )}
        </Field>
      )}
    />
  );

  const renderDnslogHost = () => (
    <Controller
      control={form.control}
      name="host"
      render={({ field, fieldState }) => (
        <Field className="gap-1" orientation="vertical" data-invalid={fieldState.invalid}>
          <FieldLabel htmlFor="dnslogHost">
            {t("probeshell:dnslog.host")}
            {requiredMark}
          </FieldLabel>
          <Input id="dnslogHost" placeholder={t("placeholders.input")} {...field} />
          {fieldState.error && <FieldError errors={[fieldState.error]} />}
        </Field>
      )}
    />
  );

  const renderRespHeaderName = () => (
    <Controller
      control={form.control}
      name="respHeaderName"
      render={({ field, fieldState }) => (
        <Field className="gap-1" data-invalid={fieldState.invalid}>
          <FieldLabel>{t("probeshell:respHeaderName")}</FieldLabel>
          <Input
            placeholder={t("probeshell:respHeaderName.placeholder")}
            aria-invalid={fieldState.invalid}
            {...field}
          />
          {fieldState.error ? (
            <FieldError errors={[fieldState.error]} />
          ) : (
            <p className="mt-1 text-xs text-muted-foreground">
              {t("probeshell:respHeaderName.description")}
            </p>
          )}
        </Field>
      )}
    />
  );

  const renderParamSection = () => (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Shuffle className="h-4 w-4" />
          <Label htmlFor="randomProbeParams" className="text-sm font-medium">
            {t("common:shellToolParam.random")}
          </Label>
        </div>
        <Switch
          id="randomProbeParams"
          checked={randomParams}
          onCheckedChange={handleRandomParamsChange}
        />
      </div>
      {!randomParams && (
        <div className="flex flex-col gap-2">
          <div className={cn("grid grid-cols-1 gap-2", showCommandTemplate && "md:grid-cols-2")}>
            {needParam && (
              <Controller
                control={form.control}
                name="reqParamName"
                render={({ field, fieldState }) => (
                  <Field className="gap-1">
                    <div className="flex items-center gap-1">
                      <FieldLabel>{t("common:paramName")}</FieldLabel>
                      <Tooltip>
                        <TooltipTrigger>{infoIcon}</TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:paramName.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                    <Input placeholder={t("placeholders.input")} {...field} />
                    {fieldState.error && <FieldError errors={[fieldState.error]} />}
                  </Field>
                )}
              />
            )}
            {showCommandTemplate && (
              <Controller
                control={form.control}
                name="commandTemplate"
                render={({ field }) => (
                  <Field className="gap-1">
                    <FieldLabel>{t("common:commandTemplate")}</FieldLabel>
                    <Input {...field} placeholder={t("common:commandTemplate.placeholder")} />
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t("common:commandTemplate.description")}
                    </p>
                  </Field>
                )}
              />
            )}
          </div>
          {isResponseHeader && renderRespHeaderName()}
        </div>
      )}
    </div>
  );

  const renderSleepSection = () => (
    <div className="space-y-2">
      <Controller
        control={form.control}
        name="sleepServer"
        render={({ field, fieldState }) => (
          <Field className="gap-1" orientation="vertical" data-invalid={fieldState.invalid}>
            <FieldLabel htmlFor="sleepServer">{t("probeshell:sleepServer")}</FieldLabel>
            <Select onValueChange={field.onChange} value={field.value || ""}>
              <SelectTrigger aria-invalid={fieldState.invalid} id="sleepServer">
                <SelectValue data-placeholder={t("placeholders.select")} />
              </SelectTrigger>
              <SelectContent>
                {MIDDLEWARE_OPTIONS.map(({ value, label }) => (
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
      <Controller
        control={form.control}
        name="seconds"
        render={({ field, fieldState }) => (
          <Field className="gap-1" orientation="vertical" data-invalid={fieldState.invalid}>
            <FieldLabel>{t("probeshell:sleepSeconds")}</FieldLabel>
            <Input
              type="number"
              placeholder={t("placeholders.input")}
              {...field}
              onChange={(event) => field.onChange(+event.target.value)}
            />
            {fieldState.error && <FieldError errors={[fieldState.error]} />}
          </Field>
        )}
      />
    </div>
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <ServerIcon className="h-4 w-4 text-muted-foreground" />
        <span>{t("probeshell:mainConfig.title")}</span>
      </div>
      <div className="flex flex-col gap-3">
        {isResponseMethod && (
          <>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {renderProbeMethod()}
              {renderServer()}
            </div>
            {renderProbeContent()}
            {showParamSection && renderParamSection()}
          </>
        )}
        {watchedProbeMethod === "DNSLog" && (
          <>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {renderProbeMethod()}
              {renderDnslogHost()}
            </div>
            {renderProbeContent()}
          </>
        )}
        {isSleepMethod && (
          <>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {renderProbeMethod()}
              {renderProbeContent()}
            </div>
            {isServerContent && renderSleepSection()}
          </>
        )}
        <div className="flex flex-col gap-4">
          <ProbeClassFormField form={form} />
          <BytecodeOptions control={form.control} />
        </div>
      </div>
      <Separator />
      <div className="flex items-center gap-2 text-sm font-semibold">
        <PackageIcon className="h-4 w-4 text-muted-foreground" />
        <span>{t("common:packerConfig.title")}</span>
      </div>
      <PackageConfigFields
        packerConfig={packerConfig}
        form={form}
        configError={packerConfigError}
        isRetrying={isPackerRetrying}
        onRetry={onRetryPacker}
      />
    </div>
  );
}
