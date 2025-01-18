import { Button, ButtonProps } from "@/components/ui/button.tsx";
import { cn } from "@/lib/utils.ts";
import { Check, Copy } from "lucide-react";
import { HTMLProps, useEffect, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { materialDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import { toast } from "sonner";

interface CopyButtonProps extends ButtonProps {
  value: string;
  src?: string;
}

export function CopyButton({ value, className, src, variant = "ghost", ...props }: CopyButtonProps) {
  const [hasCopied, setHasCopied] = useState(false);

  useEffect(() => {
    if (hasCopied) {
      setTimeout(() => {
        setHasCopied(false);
      }, 1000);
    }
  }, [hasCopied]);

  return (
    <CopyToClipboard
      text={value}
      onCopy={() => {
        setHasCopied(true);
        toast.success("复制成功", { duration: 1000 });
      }}
    >
      <Button
        size="icon"
        type="button"
        variant={variant}
        className={cn("relative z-10 h-8 w-8 text-zinc-50 hover:bg-zinc-700 hover:text-zinc-50", className)}
        {...props}
      >
        <span className="sr-only">Copy</span>
        {hasCopied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
    </CopyToClipboard>
  );
}

export function CodeViewer({
  code,
  language,
  showLineNumbers = true,
  wrapLongLines = false,
  height = 500,
}: {
  code: string;
  language: string;
  showLineNumbers?: boolean;
  wrapLongLines?: boolean;
  height?: number;
}) {
  const lineProps: lineTagPropsFunction | HTMLProps<HTMLElement> | undefined = wrapLongLines
    ? { style: { overflowWrap: "break-word", whiteSpace: "pre-wrap" } }
    : undefined;
  return (
    <div className="relative overflow-hidden text-xs wrap-all">
      <CopyButton value={code} className="absolute right-4 top-2" />
      <SyntaxHighlighter
        language={language}
        style={materialDark}
        showLineNumbers={showLineNumbers}
        wrapLongLines={wrapLongLines}
        lineProps={lineProps}
        customStyle={{
          margin: 0,
          paddingRight: showLineNumbers ? 0 : 24,
          paddingLeft: showLineNumbers ? 0 : 24,
          borderRadius: "var(--radius)",
          height: height,
          whiteSpace: wrapLongLines ? "pre-wrap" : "pre",
          overflowWrap: wrapLongLines ? "normal" : "break-word",
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
}
