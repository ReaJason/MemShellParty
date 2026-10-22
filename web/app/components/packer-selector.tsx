import type { PackerOption } from "@/types/memshell";

import { useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from "@/components/ui/combobox";
import { Field, FieldLabel } from "@/components/ui/field";

/**
 * packer 选择器。
 * - 分类（父）与变体（子）各用一个 combobox，选中某个具体子变体。
 *
 * 通过受控的 `value` / `onChange` 与表单字段 `packingMethod` 双向同步，
 * `value` 始终是单一来源；UI 状态（当前激活的父）由 `value` 推导，避免状态不一致。
 */
export default function PackerSelector({
  parents,
  value,
  onChange,
}: Readonly<{
  parents: PackerOption[];
  value: string;
  onChange: (value: string) => void;
}>) {
  const { t } = useTranslation("common");

  const values = useMemo(() => {
    return parents.flatMap((parent) =>
      parent.children.length > 0 ? parent.children : [parent.name],
    );
  }, [parents]);

  useEffect(() => {
    if (values.length === 0) {
      return;
    }

    const selectedParent = parents.find((parent) => parent.name === value);
    if (selectedParent?.children.length) {
      onChange(selectedParent.children[0]);
      return;
    }

    if (!value || !values.includes(value)) {
      const firstParent = parents[0];
      onChange(firstParent?.children[0] ?? firstParent?.name ?? values[0]);
    }
  }, [parents, values, value, onChange]);

  const activeParent = useMemo(
    () =>
      parents.find((parent) => parent.name === value || parent.children.includes(value)) ??
      parents[0],
    [parents, value],
  );

  const parentByName = useMemo(
    () => new Map(parents.map((parent) => [parent.name, parent])),
    [parents],
  );

  const categoryItems = useMemo(() => parents.map((parent) => parent.name), [parents]);

  const variantItems = useMemo(() => {
    if (!activeParent) {
      return [];
    }
    return activeParent.children.length > 0 ? activeParent.children : [activeParent.name];
  }, [activeParent]);

  const selectParent = (name: string | null) => {
    const parent = name ? parentByName.get(name) : undefined;
    if (parent) {
      onChange(parent.children[0] ?? parent.name);
    }
  };

  return (
    <div className="grid gap-3 md:grid-cols-2">
      <Field>
        <FieldLabel htmlFor="packer-category">{t("packerMode.category")}</FieldLabel>
        <Combobox
          items={categoryItems}
          value={activeParent?.name ?? null}
          onValueChange={selectParent}
        >
          <ComboboxInput id="packer-category" placeholder={t("placeholders.select")} />
          <ComboboxContent>
            <ComboboxEmpty>{t("noResults")}</ComboboxEmpty>
            <ComboboxList>
              {(name: string) => {
                const parent = parentByName.get(name);
                const hasChildren = (parent?.children.length ?? 0) > 0;
                return (
                  <ComboboxItem key={name} value={name}>
                    <span className="flex-1 font-medium whitespace-nowrap">{t(name)}</span>
                    {hasChildren && (
                      <Badge
                        variant={activeParent?.name === name ? "secondary" : "outline"}
                        className="h-5 px-1.5 text-[11px] tabular-nums"
                      >
                        {parent?.children.length}
                      </Badge>
                    )}
                  </ComboboxItem>
                );
              }}
            </ComboboxList>
          </ComboboxContent>
        </Combobox>
      </Field>
      <Field>
        <FieldLabel htmlFor="packer-variant">{t("packerMode.variant")}</FieldLabel>
        <Combobox
          items={variantItems}
          value={value || null}
          onValueChange={(next) => {
            if (next) {
              onChange(next);
            }
          }}
        >
          <ComboboxInput id="packer-variant" placeholder={t("placeholders.select")} />
          <ComboboxContent>
            <ComboboxEmpty>{t("noResults")}</ComboboxEmpty>
            <ComboboxList>
              {(name: string) => (
                <ComboboxItem key={name} value={name}>
                  <span className="flex-1 font-medium whitespace-nowrap">{t(name)}</span>
                </ComboboxItem>
              )}
            </ComboboxList>
          </ComboboxContent>
        </Combobox>
      </Field>
    </div>
  );
}
