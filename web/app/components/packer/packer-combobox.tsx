import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxGroup,
  ComboboxInput,
  ComboboxItem,
  ComboboxLabel,
  ComboboxList,
} from "@/components/ui/combobox";
import type { NormalizedPackerCategory } from "@/lib/packer-schema";

type PackerComboboxProps = {
  categories: NormalizedPackerCategory[];
  value?: string;
  onValueChange: (value: string) => void;
  placeholder?: string;
  emptyText?: string;
  disabled?: boolean;
};

type PreparedPacker = {
  name: string;
  label: string;
  searchText: string;
};

type PreparedCategory = {
  name: string;
  label: string;
  packers: PreparedPacker[];
};

export function PackerCombobox({
  categories,
  value,
  onValueChange,
  placeholder,
  emptyText,
  disabled,
}: Readonly<PackerComboboxProps>) {
  const { t } = useTranslation("common");
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const preparedCategories = useMemo<PreparedCategory[]>(
    () =>
      categories.map((category) => {
        const categoryLabel = t(category.name, { defaultValue: category.name });
        return {
          name: category.name,
          label: categoryLabel,
          packers: category.packers.map((packer) => {
            const packerLabel = t(packer.name, { defaultValue: packer.name });
            return {
              name: packer.name,
              label: packerLabel,
              searchText:
                `${packer.name} ${packerLabel} ${category.name} ${categoryLabel}`.toLowerCase(),
            };
          }),
        };
      }),
    [categories, t],
  );

  const selectedLabel = useMemo(() => {
    if (!value) {
      return "";
    }
    for (const category of preparedCategories) {
      const found = category.packers.find((packer) => packer.name === value);
      if (found) {
        return found.label;
      }
    }
    return value;
  }, [preparedCategories, value]);

  const filteredCategories = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) {
      return preparedCategories;
    }
    return preparedCategories
      .map((category) => ({
        ...category,
        packers: category.packers.filter((packer) =>
          packer.searchText.includes(normalizedQuery),
        ),
      }))
      .filter((category) => category.packers.length > 0);
  }, [preparedCategories, query]);

  const resolvedPlaceholder =
    placeholder ?? t("selectPacker", { defaultValue: "Select packer" });
  return (
    <Combobox
      value={value ?? null}
      open={open}
      onOpenChange={(nextOpen) => {
        setOpen(nextOpen);
        setQuery("");
      }}
      inputValue={open ? query : selectedLabel}
      onInputValueChange={(nextValue) => {
        if (open) {
          setQuery(nextValue);
        }
      }}
      onValueChange={(nextValue) => {
        if (typeof nextValue === "string") {
          onValueChange(nextValue);
        }
        setOpen(false);
        setQuery("");
      }}
      autoComplete="none"
      autoHighlight={true}
    >
      <ComboboxInput
        className="w-full"
        placeholder={resolvedPlaceholder}
        disabled={disabled}
        showClear={false}
      />
      <ComboboxContent>
        <ComboboxList>
          {filteredCategories.map((category) => (
            <ComboboxGroup key={category.name}>
              <ComboboxLabel>{category.label}</ComboboxLabel>
              {category.packers.map((packer) => (
                <ComboboxItem key={packer.name} value={packer.name}>
                  <span className="truncate" title={packer.label}>
                    {packer.label}
                  </span>
                </ComboboxItem>
              ))}
            </ComboboxGroup>
          ))}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  );
}
