import { PackageIcon } from "lucide-react";
import { useEffect, useMemo } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { PackerCombobox } from "@/components/packer/packer-combobox";
import { PackerCustomConfigFields } from "@/components/packer/packer-custom-config-fields";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel, FieldSet } from "@/components/ui/field";
import {
  findPackerEntry,
  getPackerDefaultConfig,
  getPackerSchemaFields,
  normalizePackerCategories,
} from "@/lib/packer-schema";
import type { PackerConfig } from "@/types/memshell";
import type { ProbeShellFormSchema } from "@/types/schema";

export default function PackageConfigCard({
  packerConfig,
  form,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<ProbeShellFormSchema>;
}>) {
  const { t } = useTranslation("common");
  const packingMethod = useWatch({
    control: form.control,
    name: "packingMethod",
  });

  const categories = useMemo(
    () => normalizePackerCategories(packerConfig),
    [packerConfig],
  );

  const filteredCategories = useMemo(() => {
    return categories
      .map((category) => ({
        ...category,
        packers: category.packers.filter((packer) => {
          if (packer.categoryAnchor) {
            return false;
          }
          const name = packer.name;
          return (
            !name.startsWith("Agent") &&
            !name.toLowerCase().startsWith("xxl") &&
            !name.toLowerCase().endsWith("jar")
          );
        }),
      }))
      .filter((category) => category.packers.length > 0);
  }, [categories]);

  const allOptionNames = useMemo(
    () =>
      filteredCategories.flatMap((category) =>
        category.packers.map((packer) => packer.name),
      ),
    [filteredCategories],
  );

  const selectedPackerEntry = useMemo(
    () =>
      findPackerEntry(filteredCategories, packingMethod) ??
      findPackerEntry(categories, packingMethod),
    [categories, filteredCategories, packingMethod],
  );

  const selectedSchemaFields = useMemo(
    () => getPackerSchemaFields(selectedPackerEntry),
    [selectedPackerEntry],
  );

  useEffect(() => {
    const currentValue = form.getValues("packingMethod");
    if (
      allOptionNames.length > 0 &&
      (!currentValue ||
        !allOptionNames.some((option) => option === currentValue))
    ) {
      form.setValue("packingMethod", allOptionNames[0]);
    }
  }, [allOptionNames, form]);

  useEffect(() => {
    form.setValue(
      "packerCustomConfig",
      getPackerDefaultConfig(selectedPackerEntry) as any,
    );
  }, [form, selectedPackerEntry, packingMethod]);

  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <PackageIcon className="h-5" />
          <span>{t("packerConfig.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {allOptionNames.length > 0 ? (
          <>
            <Controller
              control={form.control}
              name="packingMethod"
              render={({ field }) => (
                <Field className="gap-1">
                  <FieldLabel>{t("packerMethod")}</FieldLabel>
                  <PackerCombobox
                    categories={filteredCategories}
                    value={field.value}
                    onValueChange={field.onChange}
                    placeholder={t("selectPacker", {
                      defaultValue: "Select packer",
                    })}
                  />
                </Field>
              )}
            />
            <PackerCustomConfigFields
              form={form}
              fields={selectedSchemaFields}
            />
          </>
        ) : (
          <div className="flex items-center justify-center p-4">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            <span className="text-sm text-muted-foreground">
              {t("loading")}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
