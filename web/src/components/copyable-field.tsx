import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Check, Copy } from "lucide-react";
import { useCallback, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import { toast } from "sonner";

interface CopyableFieldProps {
  label: string;
  value?: string;
  text?: string;
}

export function CopyableField({ label, value, text }: CopyableFieldProps) {
  const [hasCopied, setHasCopied] = useState(false);

  const copyToClipboard = useCallback(() => {
    setHasCopied(true);
    toast.success(`复制${label}成功`, {
      duration: 1000,
    });
    setTimeout(() => {
      setHasCopied(false);
    }, 1000);
  }, [label]);

  return (
    <div className="flex items-center justify-between h-9">
      <div className="flex items-center space-x-2 text-sm">
        <Label className="w-32 text-right">{label}：</Label>
        <p>{text}</p>
      </div>
      {value && (
        <CopyToClipboard text={value as string} onCopy={copyToClipboard}>
          <Button variant="ghost" size="icon" type="button">
            {hasCopied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          </Button>
        </CopyToClipboard>
      )}
    </div>
  );
}
