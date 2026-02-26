import {
  Controller,
  type FieldValues,
  type UseFormReturn,
} from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldSet,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { PackerSchemaField } from "@/types/memshell";

type Props<T extends FieldValues> = {
  form: UseFormReturn<T>;
  fields: PackerSchemaField[];
  baseName?: string;
};

export function PackerCustomConfigFields<T extends FieldValues>({
  form,
  fields,
  baseName = "packerCustomConfig",
}: Readonly<Props<T>>) {
  const { t } = useTranslation("common");

  if (fields.length === 0) {
    return null;
  }

  const supportedFields = fields.filter((field) =>
    ["BOOLEAN", "STRING", "ENUM", "INTEGER"].includes(field.type),
  );

  if (supportedFields.length === 0) {
    return null;
  }

  const getFieldDescription = (schemaField: PackerSchemaField) => {
    if (!schemaField.description && !schemaField.descriptionI18nKey) {
      return undefined;
    }
    if (!schemaField.descriptionI18nKey) {
      return schemaField.description;
    }
    return t(schemaField.descriptionI18nKey, {
      defaultValue: schemaField.description ?? schemaField.descriptionI18nKey,
    });
  };

  return (
    <Field className="mt-2 gap-1">
      <FieldLabel>
        {t("packerParams", { defaultValue: "Packer Params" })}
      </FieldLabel>
      {supportedFields.map((schemaField) => {
        const fieldName = `${baseName}.${schemaField.key}` as any;
        const fieldDescription = getFieldDescription(schemaField);

        return (
          <Controller
            key={schemaField.key}
            control={form.control}
            name={fieldName}
            render={({ field }) => {
              switch (schemaField.type) {
                case "BOOLEAN":
                  return (
                    <Field orientation="horizontal">
                      <Switch
                        id={fieldName}
                        checked={Boolean(field.value)}
                        onCheckedChange={field.onChange}
                      />
                      <FieldContent>
                        <FieldLabel htmlFor={fieldName}>
                          {schemaField.key}
                        </FieldLabel>
                        {fieldDescription ? (
                          <FieldDescription>
                            {fieldDescription}
                          </FieldDescription>
                        ) : null}
                      </FieldContent>
                    </Field>
                  );
                case "ENUM":
                  return (
                    <Field orientation="vertical">
                      <FieldContent>
                        <FieldLabel htmlFor={fieldName}>
                          {schemaField.key}
                        </FieldLabel>
                        <Select
                          value={
                            typeof field.value === "string"
                              ? field.value
                              : undefined
                          }
                          onValueChange={field.onChange}
                        >
                          <SelectTrigger id={fieldName}>
                            <SelectValue
                              data-placeholder={t("placeholders.select")}
                            />
                          </SelectTrigger>
                          <SelectContent>
                            {(schemaField.options ?? []).map((option) => (
                              <SelectItem
                                key={option.value}
                                value={option.value}
                              >
                                {option.label || option.value}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        {fieldDescription ? (
                          <FieldDescription>
                            {fieldDescription}
                          </FieldDescription>
                        ) : null}
                      </FieldContent>
                    </Field>
                  );
                case "INTEGER":
                  return (
                    <Field orientation="vertical">
                      <FieldContent>
                        <FieldLabel htmlFor={fieldName}>
                          {schemaField.key}
                        </FieldLabel>
                        <Input
                          id={fieldName}
                          type="number"
                          step={1}
                          value={
                            typeof field.value === "number"
                              ? String(field.value)
                              : ""
                          }
                          onChange={(event) => {
                            const raw = event.target.value;
                            if (raw === "") {
                              field.onChange(undefined);
                              return;
                            }
                            const parsed = Number.parseInt(raw, 10);
                            field.onChange(
                              Number.isFinite(parsed) ? parsed : undefined,
                            );
                          }}
                        />
                        {fieldDescription ? (
                          <FieldDescription>
                            {fieldDescription}
                          </FieldDescription>
                        ) : null}
                      </FieldContent>
                    </Field>
                  );
                case "STRING":
                  return (
                    <Field orientation="vertical">
                      <FieldContent>
                        <FieldLabel htmlFor={fieldName}>
                          {schemaField.key}
                        </FieldLabel>
                        <Input
                          id={fieldName}
                          type="text"
                          value={
                            typeof field.value === "string" ? field.value : ""
                          }
                          onChange={field.onChange}
                        />
                        {fieldDescription ? (
                          <FieldDescription>
                            {fieldDescription}
                          </FieldDescription>
                        ) : null}
                      </FieldContent>
                    </Field>
                  );
                default:
                  return <></>;
              }
            }}
          />
        );
      })}
    </Field>
  );
}
