import { FormField, FormFieldItem, FormFieldLabel } from "@/components/ui/form.tsx";
import { Input } from "@/components/ui/input.tsx";
import { FormSchema } from "@/types/schema.ts";
import { ChevronDown, ChevronUp, Settings } from "lucide-react";
import { Fragment, useState } from "react";
import { FormProvider, UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Button } from "../ui/button";

export function OptionalClassFormField({ form }: Readonly<{ form: UseFormReturn<FormSchema> }>) {
  const { t } = useTranslation();
  const [showAdvanced, setShowAdvanced] = useState(false);
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
                <FormFieldLabel>
                  {t("mainConfig.shellClassName")} {t("optional")}
                </FormFieldLabel>
                <Input id="shellClassName" {...field} placeholder={t("placeholders.input")} />
              </FormFieldItem>
            )}
          />
          <FormField
            control={form.control}
            name="injectorClassName"
            render={({ field }) => (
              <FormFieldItem>
                <FormFieldLabel>
                  {t("mainConfig.injectorClassName")} {t("optional")}
                </FormFieldLabel>
                <Input id="injectorClassName" {...field} placeholder={t("placeholders.input")} />
              </FormFieldItem>
            )}
          />
        </FormProvider>
      )}
    </Fragment>
  );
}
