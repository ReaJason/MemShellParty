import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Field, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { cn, shouldHidden } from "@/lib/utils";
import type { MemShellFormSchema } from "@/types/schema";

export function UrlPatternFormField({
  form,
}: Readonly<{ form: UseFormReturn<MemShellFormSchema> }>) {
  const { t } = useTranslation("common");
  const shellType = form.watch("shellType");
  return (
    <Controller
      control={form.control}
      name="urlPattern"
      render={({ field, fieldState }) => (
        <Field
          className={cn("gap-1", shouldHidden(shellType) ? "hidden" : "grid")}
          data-invalid={fieldState.invalid}
        >
          <FieldLabel>{t("urlPattern")}</FieldLabel>
          <Input {...field} placeholder={t("placeholders.input")} />
          {fieldState.error && <FieldError errors={[fieldState.error]} />}
        </Field>
      )}
    />
  );
}
