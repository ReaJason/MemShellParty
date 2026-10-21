import { Check, Copy } from "lucide-react";
import { type ComponentPropsWithoutRef, useCallback, useEffect, useState } from "react";
import CopyToClipboard from "react-copy-to-clipboard";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

type CopyableFieldProps = {
  label: string;
  value?: string;
  text?: string;
} & Omit<ComponentPropsWithoutRef<"div">, "children">;

export function CopyableField({
  label,
  value,
  text,
  className,
  ...divProps
}: Readonly<CopyableFieldProps>) {
  const [hasCopied, setHasCopied] = useState(false);
  const { t } = useTranslation(["common"]);

  useEffect(() => {
    if (hasCopied) {
      const timer = setTimeout(() => {
        setHasCopied(false);
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [hasCopied]);

  const handleCopy = useCallback(() => {
    if (!hasCopied) {
      setHasCopied(true);
      toast.success(t("copyLabelSuccess", { label }), {
        duration: 1000,
      });
    }
  }, [hasCopied, label, t]);

  return (
    <div className={cn("flex items-center gap-2 py-0.5", className)} {...divProps}>
      <Label className="shrink-0 text-sm text-muted-foreground">{label}：</Label>
      <p className="min-w-0 flex-1 truncate text-sm" title={text}>
        {text}
      </p>
      {value && (
        <CopyToClipboard.CopyToClipboard text={value} onCopy={handleCopy}>
          <Button
            variant="ghost"
            size="icon"
            type="button"
            className="h-7 w-7 shrink-0"
            disabled={hasCopied}
          >
            {hasCopied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          </Button>
        </CopyToClipboard.CopyToClipboard>
      )}
    </div>
  );
}
