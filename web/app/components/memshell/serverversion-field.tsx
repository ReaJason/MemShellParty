import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
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

export function ServerVersionFormField({
  form,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
}>) {
  const { t } = useTranslation(["common"]);
  const server = useWatch({ control: form.control, name: "server" });
  const serverVersionOptions = getServerVersionOptions(server);
  return (
    <Controller
      control={form.control}
      name="serverVersion"
      render={({ field, fieldState }) => (
        <Field orientation="vertical" data-invalid={fieldState.invalid}>
          <FieldContent>
            <FieldLabel htmlFor="serverVersion">
              {t("common:serverVersion")}
            </FieldLabel>
            <Select onValueChange={field.onChange} value={field.value}>
              <SelectTrigger
                id="serverVersion"
                aria-invalid={fieldState.invalid}
              >
                <SelectValue
                  data-placeholder={t("common:placeholders.select")}
                />
              </SelectTrigger>
              <SelectContent>
                {serverVersionOptions.map((v) => (
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

function getServerVersionOptions(server: string) {
  if (server === "TongWeb") {
    return [
      { name: "6", value: "6" },
      { name: "7", value: "7" },
      { name: "8", value: "8" },
    ];
  } else if (server === "Jetty") {
    return [
      { name: "6", value: "6" },
      { name: "7+", value: "7+" },
      { name: "12", value: "12" },
    ];
  }
  return [{ name: "Unknown", value: "Unknown" }];
}
