import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Check, Copy } from "lucide-react";
import { useCallback, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import { toast } from "sonner";

interface CopyableFieldProps {
  label: string;
  value?: string;
  size?: number;
}

export function CopyableField({ label, value, size }: CopyableFieldProps) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = useCallback(() => {
    if (typeof value === "string") {
      navigator.clipboard.writeText(value).then(() => {
        setCopied(true);
        toast.success(`复制${label}成功`, {
          duration: 1000,
        });
        setTimeout(() => setCopied(false), 1000);
      });
    }
  }, [value, label]);

  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center space-x-2 text-sm">
        <Label className="w-24 text-right">{label}：</Label>
        <p>
          {value} {size != null && `(${size} bytes)`}
        </p>
      </div>
      <CopyToClipboard text={value as string} onCopy={copyToClipboard}>
        <Button variant="ghost" size="icon" type="button">
          {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
        </Button>
      </CopyToClipboard>
    </div>
  );
}
