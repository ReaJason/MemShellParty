import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  Field,
  FieldContent,
  FieldError,
  FieldLabel,
} from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { MemShellFormSchema } from "@/types/schema";

const JDKVersion = [
  { name: "Java6", value: "50" },
  { name: "Java8", value: "52" },
  { name: "Java9", value: "53" },
  { name: "Java11", value: "55" },
  { name: "Java17", value: "61" },
  { name: "Java21", value: "65" },
];

export function JREVersionFormField({
  form,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
}>) {
  const { t } = useTranslation(["common"]);
  return (
    <Controller
      control={form.control}
      name="targetJdkVersion"
      render={({ field, fieldState }) => (
        <Field orientation="vertical" data-invalid={fieldState.invalid}>
          <FieldContent>
            <FieldLabel htmlFor="targetJdkVersion">
              {t("common:targetJdkVersion")}
            </FieldLabel>
            <Select
              onValueChange={(v) => {
                if (Number.parseInt(v ?? "0", 10) >= 53) {
                  form.setValue("byPassJavaModule", true);
                } else {
                  form.setValue("byPassJavaModule", false);
                }
                field.onChange(v);
              }}
              value={field.value}
            >
              <SelectTrigger
                id="targetJdkVersion"
                aria-invalid={fieldState.invalid}
              >
                <SelectValue
                  data-placeholder={t("common:placeholders.select")}
                />
              </SelectTrigger>
              <SelectContent>
                {JDKVersion.map((v) => (
                  <SelectItem key={v.value} value={v.value}>
                    {v.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {fieldState.error && <FieldError errors={[fieldState.error]} />}
          </FieldContent>
        </Field>
      )}
    />
  );
}
