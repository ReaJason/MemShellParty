import { PackageIcon } from "lucide-react";
import { useEffect, useMemo } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { PackerCombobox } from "@/components/packer/packer-combobox";
import { PackerCustomConfigFields } from "@/components/packer/packer-custom-config-fields";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel, FieldSet } from "@/components/ui/field";
import { Spinner } from "@/components/ui/spinner";
import {
  findPackerEntry,
  getPackerDefaultConfig,
  getPackerSchemaFields,
  normalizePackerCategories,
} from "@/lib/packer-schema";
import type { PackerConfig } from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";

export default function PackageConfigCard({
  packerConfig,
  form,
}: Readonly<{
  packerConfig: PackerConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
}>) {
  const { t } = useTranslation("common");

  const shellType = useWatch({
    control: form.control,
    name: "shellType",
  });

  const server = useWatch({
    control: form.control,
    name: "server",
  });

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
      .map((group) => ({
        ...group,
        packers: group.packers.filter((packer) => {
          if (packer.categoryAnchor) {
            return false;
          }
          const name = packer.name;
          if (!shellType || shellType === " ") {
            return true;
          }
          if (shellType.startsWith("Agent")) {
            return name.startsWith("Agent");
          }
          if ((server ?? "").startsWith("XXL")) {
            return !name.startsWith("Agent");
          }
          return (
            !name.startsWith("Agent") && !name.toLowerCase().startsWith("xxl")
          );
        }),
      }))
      .filter((group) => group.packers.length > 0);
  }, [categories, shellType, server]);

  const allOptionNames = useMemo(
    () =>
      filteredCategories.flatMap((group) =>
        group.packers.map((packer) => packer.name),
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
    if (allOptionNames.length > 0) {
      const current = form.getValues("packingMethod");
      if (!current || !allOptionNames.includes(current)) {
        form.setValue("packingMethod", allOptionNames[0]);
      }
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
          <div className="flex items-center justify-center p-4 gap-4 h-50">
            <Spinner />
            <span className="text-sm text-muted-foreground">
              {t("loading")}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
