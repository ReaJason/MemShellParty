import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Check, Copy } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

interface CopyableFieldProps {
  label: string;
  value?: string;
  text?: string;
}

export function CopyableField({ label, value, text }: Readonly<CopyableFieldProps>) {
  const [hasCopied, setHasCopied] = useState(false);
  const { t } = useTranslation();

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
    <div className="flex flex-col gap-1 py-1">
      <div className="flex items-center justify-between gap-2 h-8">
        <Label className="text-sm text-muted-foreground">{label}：</Label>
        {value && (
          <CopyToClipboard text={value} onCopy={handleCopy}>
            <Button variant="ghost" size="icon" type="button" className="h-8 w-8" disabled={hasCopied}>
              {hasCopied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </Button>
          </CopyToClipboard>
        )}
      </div>
      <p className="text-sm break-all">{text}</p>
    </div>
  );
}
