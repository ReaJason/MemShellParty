import type { ProbeShellFormSchema } from "@/types/schema";

import { Shuffle } from "lucide-react";
import { Fragment, useEffect, useState } from "react";
import { Controller, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";

import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { SwitchFieldsPanel } from "@/components/ui/switch-fields-panel";

/**
 * 探测马类名的随机开关，交互和内存马页保持一致：
 * 默认随机（清空类名交给后端生成），关掉后才显示类名输入框并恢复之前填的值。
 */
export function ProbeClassFormField({
  form,
}: Readonly<{ form: UseFormReturn<ProbeShellFormSchema> }>) {
  const { t } = useTranslation(["probeshell", "common"]);
  const initialShellClassName = form.getValues("shellClassName") ?? "";
  const [useRandomClassName, setUseRandomClassName] = useState(() => !initialShellClassName.trim());
  const [savedShellClassName, setSavedShellClassName] = useState(initialShellClassName);
  const shellClassName = form.watch("shellClassName");

  useEffect(() => {
    if (!useRandomClassName) {
      setSavedShellClassName(shellClassName ?? "");
    }
  }, [shellClassName, useRandomClassName]);

  useEffect(() => {
    if (useRandomClassName && shellClassName?.trim()) {
      setUseRandomClassName(false);
    }
  }, [shellClassName, useRandomClassName]);

  const handleToggleRandomClass = (checked: boolean) => {
    setUseRandomClassName(checked);
    if (checked) {
      setSavedShellClassName(form.getValues("shellClassName") ?? "");
      form.setValue("shellClassName", "");
    } else {
      form.setValue("shellClassName", savedShellClassName ?? "");
    }
  };

  return (
    <Fragment>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Shuffle className="h-4 w-4" />
          <span>{t("probeshell:randomClassName")}</span>
        </div>
        <Switch
          id="randomClassName"
          checked={useRandomClassName}
          onCheckedChange={handleToggleRandomClass}
        />
      </div>

      {!useRandomClassName && (
        <SwitchFieldsPanel>
          <Controller
            control={form.control}
            name="shellClassName"
            render={({ field }) => (
              <Field className="gap-1.5">
                <FieldLabel htmlFor="shellClassName">{t("probeshell:shellClassName")}</FieldLabel>
                <Input
                  id="shellClassName"
                  {...field}
                  placeholder={t("common:placeholders.input")}
                />
              </Field>
            )}
          />
        </SwitchFieldsPanel>
      )}
    </Fragment>
  );
}
