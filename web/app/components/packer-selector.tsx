import type { PackerOption } from "@/types/memshell";

import { Check, ChevronRight } from "lucide-react";
import { useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

/** A leading radio-style indicator shared by every list item for a consistent look. */
function RadioDot({ active }: Readonly<{ active: boolean }>) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex size-3.5 shrink-0 items-center justify-center rounded-full border transition-colors",
        active ? "border-sidebar-accent-foreground" : "border-muted-foreground/40",
      )}
    >
      <span
        className={cn(
          "size-1.5 rounded-full bg-sidebar-accent-foreground transition-transform",
          active ? "scale-100" : "scale-0",
        )}
      />
    </span>
  );
}

function ListItem({
  label,
  active,
  onClick,
  trailing,
}: Readonly<{
  label: string;
  active: boolean;
  onClick: () => void;
  trailing?: React.ReactNode;
}>) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={active}
      onClick={onClick}
      className={cn(
        "flex min-h-8 items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-xs leading-5 transition-colors",
        active
          ? "bg-sidebar-accent text-sidebar-accent-foreground"
          : "text-foreground hover:bg-sidebar-accent/70 hover:text-sidebar-accent-foreground",
      )}
    >
      <RadioDot active={active} />
      <span className="flex-1 font-medium break-all">{label}</span>
      {trailing}
    </button>
  );
}

/**
 * packer 选择器。
 * - 左侧分类（父）+ 右侧变体（子）的主从布局，选中某个具体子变体。
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

  const selectParent = (parent: PackerOption) => {
    onChange(parent.children[0] ?? parent.name);
  };

  const isParentActive = (parent: PackerOption) => activeParent?.name === parent.name;

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">{t("packerMode.advancedDesc")}</p>

      <div className="grid gap-3 md:grid-cols-2">
        <section className="flex flex-col">
          <div className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {t("packerMode.category")}
          </div>
          <ScrollArea className="h-64 rounded-md border">
            <div
              role="radiogroup"
              aria-label={t("packerMethod")}
              className="flex flex-col gap-0.5 p-1.5"
            >
              {parents.map((parent) => {
                const active = isParentActive(parent);
                const hasChildren = parent.children.length > 0;
                return (
                  <ListItem
                    key={parent.name}
                    label={t(parent.name)}
                    active={active}
                    onClick={() => selectParent(parent)}
                    trailing={
                      hasChildren ? (
                        <span className="flex items-center gap-1.5">
                          <Badge
                            variant={active ? "secondary" : "outline"}
                            className="h-5 px-1.5 text-[11px] tabular-nums"
                          >
                            {parent.children.length}
                          </Badge>
                          <ChevronRight className="size-4 shrink-0 opacity-70" aria-hidden="true" />
                        </span>
                      ) : undefined
                    }
                  />
                );
              })}
            </div>
          </ScrollArea>
        </section>

        <section className="flex flex-col">
          <div className="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {t("packerMode.variant")}
          </div>
          <ScrollArea className="h-64 rounded-md border">
            {activeParent && activeParent.children.length > 0 ? (
              <div
                role="radiogroup"
                aria-label={t("packerMode.variant")}
                className="flex flex-col gap-0.5 p-1.5"
              >
                {activeParent.children.map((child) => (
                  <ListItem
                    key={child}
                    label={t(child)}
                    active={value === child}
                    onClick={() => onChange(child)}
                  />
                ))}
              </div>
            ) : (
              <div className="flex h-64 flex-col items-center justify-center gap-2 px-6 text-center text-sm text-muted-foreground">
                <Check className="size-6 text-primary" aria-hidden="true" />
                <span>
                  <span className="font-medium text-foreground">{t(activeParent?.name ?? "")}</span>{" "}
                  {t("packerMode.noVariants")}
                </span>
              </div>
            )}
          </ScrollArea>
        </section>
      </div>
    </div>
  );
}
