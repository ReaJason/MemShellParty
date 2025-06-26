import { ChevronDown, ChevronUp, Settings } from "lucide-react";
import { Fragment, useId, useState } from "react";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FormField, FormFieldItem, FormFieldLabel } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { FormSchema } from "@/types/schema.ts";
import { Button } from "../ui/button";

export function OptionalClassFormField({ form }: Readonly<{ form: UseFormReturn<FormSchema> }>) {
  const { t } = useTranslation();
  const [showAdvanced, setShowAdvanced] = useState(false);
  const shellClassNameId = useId();
  const injectClassNameId = useId();
  return (
    <Fragment>
      <div className="pt-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2"
        >
          <Settings className="h-4 w-4" />
          {t("classNameOptions")}
          {showAdvanced ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </Button>
      </div>
      {showAdvanced && (
        <FormProvider {...form}>
          <FormField
            control={form.control}
            name="shellClassName"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel htmlFor={shellClassNameId}>
                  {t("mainConfig.shellClassName")} {t("optional")}
                </FormFieldLabel>
                <Input id={shellClassNameId} {...field} placeholder={t("placeholders.input")} />
              </FormFieldItem>
            )}
          />
          <FormField
            control={form.control}
            name="injectorClassName"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel htmlFor={injectClassNameId}>
                  {t("mainConfig.injectorClassName")} {t("optional")}
                </FormFieldLabel>
                <Input id={injectClassNameId} {...field} placeholder={t("placeholders.input")} />
              </FormFieldItem>
            )}
          />
        </FormProvider>
      )}
    </Fragment>
  );
}
