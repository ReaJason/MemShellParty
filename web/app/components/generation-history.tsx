import type { GenerationRecord } from "@/types/history";

import { Star, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { formatRelativeTime } from "@/lib/generation-history";
import { cn, formatBytes } from "@/lib/utils";

interface GenerationHistoryPanelProps<T extends GenerationRecord> {
  records: T[];
  currentRecordId: string | null;
  /** 「记录生成历史」开关，默认关闭（无痕生成） */
  enabled: boolean;
  onToggleEnabled: (enabled: boolean) => void;
  onSelect: (record: T) => void;
  onDelete: (id: string) => void;
  onClearAll: () => void;
  onToggleUsed: (record: T) => void;
  /** 配置摘要，如 Tomcat / Godzilla / Listener / Base64 */
  describe: (record: T) => string;
  /** 结果大小（字节） */
  sizeOf: (record: T) => number;
}

export function GenerationHistoryPanel<T extends GenerationRecord>({
  records,
  currentRecordId,
  enabled,
  onToggleEnabled,
  onSelect,
  onDelete,
  onClearAll,
  onToggleUsed,
  describe,
  sizeOf,
}: Readonly<GenerationHistoryPanelProps<T>>) {
  const { t } = useTranslation(["common"]);
  const [clearDialogOpen, setClearDialogOpen] = useState(false);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <label className="flex cursor-pointer items-center gap-2 text-sm">
          <Switch
            size="sm"
            checked={enabled}
            onCheckedChange={(checked) => onToggleEnabled(checked)}
          />
          {t("common:history.enable")}
        </label>
        {records.length > 0 && (
          <AlertDialog open={clearDialogOpen} onOpenChange={setClearDialogOpen}>
            <AlertDialogTrigger
              render={<Button variant="ghost" size="sm" className="h-7 text-muted-foreground" />}
            >
              {t("common:history.clearAll")}
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{t("common:history.clearAllConfirm.title")}</AlertDialogTitle>
                <AlertDialogDescription>
                  {t("common:history.clearAllConfirm.description", { count: records.length })}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t("common:cancel")}</AlertDialogCancel>
                <AlertDialogAction
                  variant="destructive"
                  onClick={() => {
                    onClearAll();
                    setClearDialogOpen(false);
                  }}
                >
                  {t("common:confirm")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
      </div>
      <p className="text-xs text-muted-foreground">{t("common:history.privacyHint")}</p>
      {records.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          {enabled ? t("common:history.empty") : t("common:history.disabledEmpty")}
        </p>
      ) : (
        <ul className="flex flex-col gap-1">
          {records.map((record) => (
            <li
              key={record.id}
              className={cn(
                "flex items-center gap-1 rounded-md border border-transparent px-2 py-1.5 transition-colors hover:bg-muted/50",
                record.id === currentRecordId && "border-border bg-muted/50",
              )}
            >
              <Button
                variant="ghost"
                size="icon-xs"
                type="button"
                aria-label={
                  record.used ? t("common:history.unmarkUsed") : t("common:history.markUsed")
                }
                title={record.used ? t("common:history.unmarkUsed") : t("common:history.markUsed")}
                onClick={() => onToggleUsed(record)}
              >
                <Star
                  className={cn(
                    record.used ? "fill-yellow-500 text-yellow-500" : "text-muted-foreground",
                  )}
                />
              </Button>
              <button
                type="button"
                className="min-w-0 flex-1 cursor-pointer text-left"
                onClick={() => onSelect(record)}
              >
                <span
                  className="text-xs text-muted-foreground"
                  title={new Date(record.createdAt).toLocaleString()}
                >
                  {formatRelativeTime(t, record.createdAt)}
                </span>
                <span className="block truncate text-xs">{describe(record)}</span>
              </button>
              <span className="shrink-0 text-xs text-muted-foreground">
                {formatBytes(sizeOf(record))}
              </span>
              <Button
                variant="ghost"
                size="icon-xs"
                type="button"
                aria-label={t("common:history.delete")}
                title={t("common:history.delete")}
                onClick={() => onDelete(record.id)}
              >
                <Trash2 className="text-muted-foreground" />
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
