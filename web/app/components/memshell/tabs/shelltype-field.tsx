import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  Field,
  FieldContent,
  FieldError,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn, notNeedUrlPattern } from "@/lib/utils";
import type { MemShellFormSchema } from "@/types/schema";

export function ShellTypeFormField({
  form,
  shellTypes,
}: Readonly<{
  form: UseFormReturn<MemShellFormSchema>;
  shellTypes: Array<string>;
}>) {
  const { t } = useTranslation(["memshell", "common"]);
  const shellType = useWatch({ control: form.control, name: "shellType" });
  const server = useWatch({ control: form.control, name: "server" });
  const needSelectServerVersion =
    (server === "TongWeb" && shellType.endsWith("Valve")) ||
    (server === "Jetty" &&
      (shellType === "Handler" || shellType === "JakartaHandler"));
  const needUrlPattern = !notNeedUrlPattern(shellType);
  const serverVersionOptions = getServerVersionOptions(server);
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
      <Controller
        control={form.control}
        name="shellType"
        render={({ field }) => (
          <Field className="gap-1">
            <FieldLabel>{t("mainConfig.shellMountType")}</FieldLabel>
            <Select
              onValueChange={(e) => {
                form.resetField("urlPattern");
                field.onChange(e);
              }}
              value={field.value}
            >
              <SelectTrigger>
                <SelectValue
                  data-placeholder={t("common:placeholders.select")}
                />
              </SelectTrigger>
              <SelectContent key={shellTypes?.join(",")}>
                {shellTypes?.length ? (
                  shellTypes.map((v) => (
                    <SelectItem key={v} value={v}>
                      {v}
                    </SelectItem>
                  ))
                ) : (
                  <SelectItem value=" ">
                    {t("tips.shellToolNotSelected")}
                  </SelectItem>
                )}
              </SelectContent>
            </Select>
          </Field>
        )}
      />
      <Controller
        control={form.control}
        name="urlPattern"
        render={({ field, fieldState }) => (
          <Field
            className={cn("gap-1", needUrlPattern ? "grid" : "hidden")}
            data-invalid={fieldState.invalid}
          >
            <FieldLabel>{t("common:urlPattern")}</FieldLabel>
            <Input {...field} placeholder={t("common:placeholders.input")} />
            {fieldState.error && <FieldError errors={[fieldState.error]} />}
          </Field>
        )}
      />
      <Controller
        control={form.control}
        name="serverVersion"
        render={({ field, fieldState }) => (
          <Field
            className={cn("gap-1", needSelectServerVersion ? "grid" : "hidden")}
            orientation="vertical"
            data-invalid={fieldState.invalid}
          >
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
    </div>
  );
}

function getServerVersionOptions(server: string) {
  let serverVersionOptions = [] as { name: string; value: string }[];
  if (server === "TongWeb") {
    serverVersionOptions = [
      { name: "6", value: "6" },
      { name: "7", value: "7" },
      { name: "8", value: "8" },
    ];
  } else if (server === "Jetty") {
    serverVersionOptions = [
      { name: "6", value: "6" },
      { name: "7+", value: "7+" },
      { name: "12", value: "12" },
    ];
  }
  return serverVersionOptions;
}
