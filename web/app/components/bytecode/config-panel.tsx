import type { BytecodeFormValues } from "@/types/bytecode";
import type { PackerConfig } from "@/types/memshell";

import { FileCode2Icon, InfoIcon, PackageIcon, Replace, Shuffle } from "lucide-react";
import { useRef } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { ConfigLoadError } from "@/components/config-load-error";
import PackerSelector from "@/components/packer-selector";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Separator } from "@/components/ui/separator";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

const MAX_CLASS_BYTES = 8 * 1024 * 1024;

type TextOptionName = "relocateFrom" | "relocateTo" | "newClassName";
type ToggleOptionName = "byPassJavaModule" | "staticInitialize" | "shrink";

const TOGGLE_OPTIONS: Array<{
  name: ToggleOptionName;
  labelKey: string;
  descriptionKey: string;
}> = [
  {
    name: "byPassJavaModule",
    labelKey: "common:byPassJavaModule",
    descriptionKey: "common:byPassJavaModule.description",
  },
  {
    name: "staticInitialize",
    labelKey: "common:staticInitialize",
    descriptionKey: "common:staticInitialize.description",
  },
  { name: "shrink", labelKey: "common:shrink", descriptionKey: "common:shrink.description" },
];

export function BytecodeConfigPanel({
  form,
  packerConfig,
  packerError,
  isPackerRetrying,
  onRetryPacker,
}: Readonly<{
  form: UseFormReturn<BytecodeFormValues>;
  packerConfig: PackerConfig | undefined;
  packerError: Error | null;
  isPackerRetrying: boolean;
  onRetryPacker: () => void;
}>) {
  const { t } = useTranslation(["bytecode", "common"]);
  const inputMode = useWatch({ control: form.control, name: "inputMode" });
  const randomName = useWatch({ control: form.control, name: "randomName" });
  const renamePackage = useWatch({ control: form.control, name: "renamePackage" });
  const fileName = useWatch({ control: form.control, name: "fileName" });
  const fileReadGeneration = useRef(0);

  const readClassFile = (file: File | undefined) => {
    const generation = ++fileReadGeneration.current;
    form.setValue("fileClassBase64", "", { shouldDirty: true });
    form.setValue("fileName", file?.name ?? "", { shouldDirty: true });
    if (!file) return;
    if (file.size > MAX_CLASS_BYTES) {
      toast.error(t("input.fileTooLarge"));
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      if (generation !== fileReadGeneration.current) return;
      const result = typeof reader.result === "string" ? reader.result : "";
      form.setValue("fileClassBase64", result.split(",")[1] ?? "", { shouldDirty: true });
    };
    reader.onerror = () => {
      if (generation === fileReadGeneration.current) {
        toast.error(t("input.parseFailed", { error: reader.error?.message ?? "FileReader" }));
      }
    };
    reader.readAsDataURL(file);
  };

  return (
    <div className="flex flex-col gap-5">
      <section className="flex flex-col gap-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <FileCode2Icon className="h-4 w-4 text-muted-foreground" />
          {t("input.title")}
        </h2>
        <Controller
          control={form.control}
          name="inputMode"
          render={({ field }) => (
            <RadioGroup
              value={field.value}
              onValueChange={(value) => {
                fileReadGeneration.current += 1;
                form.setValue("classBase64", "");
                form.setValue("fileClassBase64", "");
                form.setValue("fileName", "");
                field.onChange(value);
              }}
              className="flex flex-wrap items-center gap-4"
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem value="base64" id="bytecode-input-base64" />
                <Label htmlFor="bytecode-input-base64">{t("input.base64")}</Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="file" id="bytecode-input-file" />
                <Label htmlFor="bytecode-input-file">{t("input.file")}</Label>
              </div>
            </RadioGroup>
          )}
        />
        {inputMode === "base64" ? (
          <Controller
            control={form.control}
            name="classBase64"
            render={({ field }) => (
              <Field>
                <FieldLabel htmlFor="bytecode-base64" className="sr-only">
                  {t("input.base64")}
                </FieldLabel>
                <Textarea
                  {...field}
                  id="bytecode-base64"
                  placeholder={t("input.placeholder")}
                  className="h-64 resize-y font-mono text-xs"
                />
              </Field>
            )}
          />
        ) : (
          <Field>
            <FieldLabel htmlFor="bytecode-class-file" className="sr-only">
              {t("input.file")}
            </FieldLabel>
            <Input
              id="bytecode-class-file"
              type="file"
              accept=".class"
              onChange={(event) => readClassFile(event.target.files?.[0])}
            />
            {fileName && <p className="truncate text-xs text-muted-foreground">{fileName}</p>}
          </Field>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <Separator />
        <div className="flex items-center justify-between gap-3 pt-2">
          <Label
            htmlFor="bytecode-randomName"
            className="flex items-center gap-2 text-sm font-medium"
          >
            <Shuffle className="h-4 w-4" />
            <span>{t("options.randomName")}</span>
          </Label>
          <Controller
            control={form.control}
            name="randomName"
            render={({ field }) => (
              <Switch
                id="bytecode-randomName"
                aria-label={t("options.randomName")}
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            )}
          />
        </div>
        {!randomName && (
          <TextOption form={form} name="newClassName" label={t("options.className")} />
        )}

        <div className="flex items-center justify-between gap-3 pt-2">
          <Label
            htmlFor="bytecode-renamePackage"
            className="flex items-center gap-2 text-sm font-medium"
          >
            <Replace className="h-4 w-4" />
            <span>{t("options.renamePackage")}</span>
          </Label>
          <Controller
            control={form.control}
            name="renamePackage"
            render={({ field }) => (
              <Switch
                id="bytecode-renamePackage"
                aria-label={t("options.renamePackage")}
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            )}
          />
        </div>
        {renamePackage && (
          <div className="grid gap-3 md:grid-cols-2">
            <TextOption
              form={form}
              name="relocateFrom"
              label={t("options.relocateFrom")}
              placeholder="javax.servlet"
              required
            />
            <TextOption
              form={form}
              name="relocateTo"
              label={t("options.relocateTo")}
              placeholder="jakarta.servlet"
              required
            />
          </div>
        )}

        <Separator />
        <div className="@container pt-1">
          <div className="grid grid-cols-1 gap-4 @xs:grid-cols-2 @lg:grid-cols-3">
            {TOGGLE_OPTIONS.map((option) => (
              <ToggleOption key={option.name} form={form} option={option} />
            ))}
          </div>
        </div>
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <PackageIcon className="h-4 w-4 text-muted-foreground" />
          {t("common:packerConfig.title")}
        </h2>
        {packerError ? (
          <ConfigLoadError
            className="h-40"
            error={packerError}
            isRetrying={isPackerRetrying}
            onRetry={onRetryPacker}
          />
        ) : !packerConfig?.length ? (
          <div className="flex h-32 items-center justify-center gap-3">
            <Spinner />
            <span className="text-sm text-muted-foreground">{t("common:loading")}</span>
          </div>
        ) : (
          <Controller
            control={form.control}
            name="packer"
            render={({ field }) => (
              <PackerSelector
                parents={packerConfig}
                value={field.value}
                onChange={field.onChange}
              />
            )}
          />
        )}
      </section>
    </div>
  );
}

function TextOption({
  form,
  name,
  label,
  placeholder,
  required = false,
}: Readonly<{
  form: UseFormReturn<BytecodeFormValues>;
  name: TextOptionName;
  label: string;
  placeholder?: string;
  required?: boolean;
}>) {
  const { t } = useTranslation("common");
  const id = `bytecode-${name}`;
  return (
    <Controller
      control={form.control}
      name={name}
      render={({ field }) => (
        <Field>
          <FieldLabel htmlFor={id}>{label}</FieldLabel>
          <Input
            {...field}
            id={id}
            placeholder={placeholder ?? t("placeholders.input")}
            required={required}
          />
        </Field>
      )}
    />
  );
}

function ToggleOption({
  form,
  option,
}: Readonly<{
  form: UseFormReturn<BytecodeFormValues>;
  option: (typeof TOGGLE_OPTIONS)[number];
}>) {
  const { t } = useTranslation(["common"]);
  const id = `bytecode-${option.name}`;
  return (
    <Controller
      control={form.control}
      name={option.name}
      render={({ field }) => (
        <div className="flex items-center gap-2">
          <Checkbox id={id} checked={field.value} onCheckedChange={field.onChange} />
          <Label htmlFor={id} className="whitespace-nowrap">
            {t(option.labelKey)}
          </Label>
          <Tooltip>
            <TooltipTrigger>
              <InfoIcon className="h-3.5 w-3.5 cursor-help text-muted-foreground" />
            </TooltipTrigger>
            <TooltipContent>
              <p>{t(option.descriptionKey)}</p>
            </TooltipContent>
          </Tooltip>
        </div>
      )}
    />
  );
}
