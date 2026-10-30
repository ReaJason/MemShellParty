import { MessageSquareReply } from "lucide-react";
import {
  Controller,
  type FieldValues,
  type Path,
  type UseFormReturn,
  useWatch,
} from "react-hook-form";
import { useTranslation } from "react-i18next";

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
import { Switch } from "@/components/ui/switch";
import { SwitchFieldsPanel } from "@/components/ui/switch-fields-panel";
import { cn } from "@/lib/utils";

const PROBE_METHOD_OPTIONS = [
  { value: "ResponseBody", label: "Response Body" },
  { value: "ResponseHeader", label: "Response Header" },
];

interface ProbeOptionsFormValues extends FieldValues {
  probe?: boolean;
  probeMethod?: string;
  respHeaderName?: string;
  server?: string;
}

interface ProbeOptionsFieldProps<T extends ProbeOptionsFormValues> {
  readonly form: UseFormReturn<T>;
  readonly showServer?: boolean;
  readonly responseServers?: string[];
  readonly serversError?: Error | null;
  readonly isServersRetrying?: boolean;
  readonly onRetryServers?: () => void;
}

export function ProbeOptionsField<T extends ProbeOptionsFormValues>({
  form,
  showServer = false,
  responseServers,
  serversError = null,
  isServersRetrying = false,
  onRetryServers = () => {},
}: ProbeOptionsFieldProps<T>) {
  const { t } = useTranslation(["common", "memshell"]);
  const probe = useWatch({ control: form.control, name: "probe" as Path<T> });
  const probeMethod = useWatch({
    control: form.control,
    name: "probeMethod" as Path<T>,
  }) as string | undefined;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <MessageSquareReply className="h-4 w-4" />
          <Label htmlFor="probe" className="text-sm font-medium">
            {t("common:probe")}
          </Label>
        </div>
        <Controller
          control={form.control}
          name={"probe" as Path<T>}
          render={({ field }) => (
            <Switch id="probe" checked={Boolean(field.value)} onCheckedChange={field.onChange} />
          )}
        />
      </div>

      {probe && (
        <SwitchFieldsPanel
          className={cn(
            "grid grid-cols-1 gap-3",
            (showServer || probeMethod === "ResponseHeader") && "md:grid-cols-2",
          )}
        >
          {showServer && (
            <Controller
              control={form.control}
              name={"server" as Path<T>}
              render={({ field }) => (
                <Field className="gap-1">
                  <FieldLabel htmlFor="probeServer">{t("common:server")}</FieldLabel>
                  <Select
                    items={responseServers?.map((server) => ({ value: server, label: server }))}
                    onValueChange={field.onChange}
                    value={field.value || "Unknown"}
                  >
                    <SelectTrigger id="probeServer" aria-required="true">
                      <SelectValue data-placeholder={t("common:placeholders.select")} />
                    </SelectTrigger>
                    <SelectContent>
                      {responseServers?.map((server) => (
                        <SelectItem key={server} value={server}>
                          {server}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
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
          )}
          <Controller
            control={form.control}
            name={"probeMethod" as Path<T>}
            render={({ field }) => (
              <Field className="gap-1">
                <FieldLabel htmlFor="probeMethod">{t("memshell:probeMethod")}</FieldLabel>
                <Select
                  items={PROBE_METHOD_OPTIONS}
                  onValueChange={field.onChange}
                  value={field.value || "ResponseBody"}
                >
                  <SelectTrigger id="probeMethod">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROBE_METHOD_OPTIONS.map(({ value, label }) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            )}
          />
          {probeMethod === "ResponseHeader" && (
            <Controller
              control={form.control}
              name={"respHeaderName" as Path<T>}
              rules={{
                validate: (value) =>
                  !value?.trim() ||
                  /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value.trim()) ||
                  t("memshell:tips.responseHeader.name.invalid"),
              }}
              render={({ field, fieldState }) => (
                <Field
                  className={cn("gap-1", showServer && "md:col-span-2")}
                  data-invalid={fieldState.invalid}
                >
                  <FieldLabel htmlFor="respHeaderName">{t("memshell:respHeaderName")}</FieldLabel>
                  <Input
                    id="respHeaderName"
                    placeholder={t("memshell:respHeaderName.placeholder")}
                    aria-invalid={fieldState.invalid}
                    {...field}
                  />
                  {fieldState.error && <FieldError errors={[fieldState.error]} />}
                </Field>
              )}
            />
          )}
        </SwitchFieldsPanel>
      )}
    </div>
  );
}
