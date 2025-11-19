import { Shuffle } from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  FormField,
  FormFieldItem,
  FormFieldLabel,
} from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Switch } from "@/components/ui/switch.tsx";
import type { MemShellFormSchema } from "@/types/schema.ts";

export function OptionalClassFormField({
  form,
}: Readonly<{ form: UseFormReturn<MemShellFormSchema> }>) {
  const { t } = useTranslation(["memshell", "common"]);
  const initialShellClassName = form.getValues("shellClassName") ?? "";
  const initialInjectorClassName = form.getValues("injectorClassName") ?? "";
  const [useRandomClassName, setUseRandomClassName] = useState(
    () => !(initialShellClassName?.trim() || initialInjectorClassName?.trim()),
  );
  const [savedShellClassName, setSavedShellClassName] = useState(
    initialShellClassName,
  );
  const [savedInjectorClassName, setSavedInjectorClassName] = useState(
    initialInjectorClassName,
  );
  const shellClassName = form.watch("shellClassName");
  const injectorClassName = form.watch("injectorClassName");

  useEffect(() => {
    if (!useRandomClassName) {
      setSavedShellClassName(shellClassName ?? "");
    }
  }, [shellClassName, useRandomClassName]);

  useEffect(() => {
    if (!useRandomClassName) {
      setSavedInjectorClassName(injectorClassName ?? "");
    }
  }, [injectorClassName, useRandomClassName]);

  useEffect(() => {
    if (
      useRandomClassName &&
      (shellClassName?.trim() || injectorClassName?.trim())
    ) {
      setUseRandomClassName(false);
    }
  }, [injectorClassName, shellClassName, useRandomClassName]);

  const handleToggleRandomClass = (checked: boolean) => {
    setUseRandomClassName(checked);
    if (checked) {
      setSavedShellClassName(form.getValues("shellClassName") ?? "");
      setSavedInjectorClassName(form.getValues("injectorClassName") ?? "");
      form.setValue("shellClassName", "");
      form.setValue("injectorClassName", "");
    } else {
      form.setValue("shellClassName", savedShellClassName ?? "");
      form.setValue("injectorClassName", savedInjectorClassName ?? "");
    }
  };

  return (
    <Fragment>
      <div className="pt-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm">
          <Shuffle className="h-4 w-4" />
          <span>{t("mainConfig.randomClassName")}</span>
        </div>
        <Switch
          id="randomClassName"
          checked={useRandomClassName}
          onCheckedChange={handleToggleRandomClass}
        />
      </div>
      <FormProvider {...form}>
        {!useRandomClassName && (
          <FormField
            control={form.control}
            name="shellClassName"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel htmlFor="shellClassName">
                  {t("mainConfig.shellClassName")} {t("common:optional")}
                </FormFieldLabel>
                <Input
                  id="shellClassName"
                  {...field}
                  placeholder={t("common:placeholders.input")}
                />
              </FormFieldItem>
            )}
          />
        )}
        {!useRandomClassName && (
          <FormField
            control={form.control}
            name="injectorClassName"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel htmlFor="injectClassName">
                  {t("mainConfig.injectorClassName")} {t("common:optional")}
                </FormFieldLabel>
                <Input
                  id="injectClassName"
                  {...field}
                  placeholder={t("common:placeholders.input")}
                />
              </FormFieldItem>
            )}
          />
        )}
      </FormProvider>
    </Fragment>
  );
}
