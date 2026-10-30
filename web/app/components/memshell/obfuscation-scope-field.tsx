import type { ObfuscationScope } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";
import type { Control } from "react-hook-form";

import { Controller } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Field, FieldLabel } from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const SCOPE_OPTIONS: Array<{ value: ObfuscationScope; labelKey: string }> = [
  { value: "ALL", labelKey: "obfuscationScope.all" },
  { value: "MEMSHELL_INJECTOR", labelKey: "obfuscationScope.memshellInjector" },
  { value: "INJECTOR", labelKey: "obfuscationScope.injector" },
  { value: "MEMSHELL", labelKey: "obfuscationScope.memshell" },
];

export function ObfuscationScopeField({
  control,
}: Readonly<{ control: Control<MemShellFormSchema> }>) {
  const { t } = useTranslation(["memshell"]);

  return (
    <Controller
      control={control}
      name="obfuscationScope"
      render={({ field }) => (
        <Field className="gap-1.5">
          <FieldLabel htmlFor="obfuscationScope">{t("memshell:obfuscationScope")}</FieldLabel>
          <Select
            items={SCOPE_OPTIONS.map((option) => ({
              value: option.value,
              label: t(`memshell:${option.labelKey}`),
            }))}
            onValueChange={field.onChange}
            value={field.value ?? "ALL"}
          >
            <SelectTrigger id="obfuscationScope">
              <SelectValue data-placeholder={t("memshell:obfuscationScope")} />
            </SelectTrigger>
            <SelectContent>
              {SCOPE_OPTIONS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {t(`memshell:${option.labelKey}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
      )}
    />
  );
}
