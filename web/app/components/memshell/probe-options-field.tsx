import type { MemShellFormSchema } from "@/types/schema";

import { MessageSquareReply } from "lucide-react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";

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
import { cn } from "@/lib/utils";

const PROBE_METHOD_OPTIONS = [
  { value: "ResponseBody", label: "Response Body" },
  { value: "ResponseHeader", label: "Response Header" },
];

export function ProbeOptionsField({ form }: Readonly<{ form: UseFormReturn<MemShellFormSchema> }>) {
  const { t } = useTranslation(["common", "memshell"]);
  const probe = useWatch({ control: form.control, name: "probe" });
  const probeMethod = useWatch({ control: form.control, name: "probeMethod" });

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
          name="probe"
          render={({ field }) => (
            <Switch id="probe" checked={Boolean(field.value)} onCheckedChange={field.onChange} />
          )}
        />
      </div>

      {probe && (
        <div
          className={cn(
            "grid grid-cols-1 gap-2",
            probeMethod === "ResponseHeader" && "md:grid-cols-2",
          )}
        >
          <Controller
            control={form.control}
            name="probeMethod"
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
              name="respHeaderName"
              render={({ field, fieldState }) => (
                <Field className="gap-1" data-invalid={fieldState.invalid}>
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
        </div>
      )}
    </div>
  );
}
