import { AlertCircle, RotateCcwIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * 配置接口失败时的占位。与「加载中」区分开：请求已经失败就给出错误信息和重试入口，
 * 而不是继续转圈等待一个不会自动结束的查询。
 */
export function ConfigLoadError({
  error,
  onRetry,
  isRetrying = false,
  className,
}: Readonly<{
  error?: Error | null;
  onRetry: () => void;
  isRetrying?: boolean;
  className?: string;
}>) {
  const { t } = useTranslation(["common"]);

  return (
    <div
      className={cn("flex flex-col items-center justify-center gap-3 p-4 text-center", className)}
    >
      <AlertCircle className="h-6 w-6 text-destructive" />
      <div className="max-w-sm space-y-1">
        <p className="text-sm font-medium">{t("common:configLoadError.title")}</p>
        <p className="text-xs text-muted-foreground">{t("common:configLoadError.description")}</p>
        {error?.message && (
          <p className="font-mono text-xs break-all text-muted-foreground/70">
            {error.name === "TimeoutError" ? t("common:configLoadError.timeout") : error.message}
          </p>
        )}
      </div>
      <Button type="button" variant="outline" size="sm" onClick={onRetry} disabled={isRetrying}>
        <RotateCcwIcon className={cn(isRetrying && "animate-spin")} />
        {isRetrying ? t("common:configLoadError.retrying") : t("common:configLoadError.retry")}
      </Button>
    </div>
  );
}
