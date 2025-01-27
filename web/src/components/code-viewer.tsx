import { Button, ButtonProps } from "@/components/ui/button.tsx";
import { Check, Copy } from "lucide-react";
import { HTMLProps, ReactNode, useEffect, useState } from "react";
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
      <Button variant="ghost" size="icon" type="button" className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4">
        {hasCopied ? <Check /> : <Copy />}
      </Button>
    </CopyToClipboard>
  );
}

export function CodeViewer({
  code,
  header,
  language,
  height,
  showLineNumbers = true,
  wrapLongLines = true,
}: CodeViewerProps) {
  const lineProps: lineTagPropsFunction | HTMLProps<HTMLElement> | undefined = wrapLongLines
    ? { style: { overflowWrap: "break-word", whiteSpace: "pre-wrap" } }
    : undefined;
  return (
    <div className="rounded-lg border">
      {header && (
        <div className="flex items-center justify-between border-b p-2">
          {header}
          <CopyButton value={code} variant="ghost" size="sm" />
        </div>
      )}
      {!header && (
        <div className="flex items-center justify-end border-b p-2">
          <CopyButton value={code} variant="ghost" size="sm" />
        </div>
      )}
      <div className="relative overflow-hidden text-xs wrap-all">
        <SyntaxHighlighter
          language={language}
          style={materialDark}
          showLineNumbers={showLineNumbers}
          wrapLongLines={wrapLongLines}
          lineProps={lineProps}
          customStyle={{
            margin: 0,
            padding: showLineNumbers ? 0 : "1em 1em",
            borderRadius: "0 0 var(--radius) var(--radius)",
            height: height,
            whiteSpace: wrapLongLines ? "pre-wrap" : "pre",
            overflowWrap: wrapLongLines ? "normal" : "break-word",
          }}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    </div>
  );
}

interface CodeViewerProps {
  code: string;
  language: string;
  header?: ReactNode;
  height?: string | number;
  showLineNumbers?: boolean;
  wrapLongLines?: boolean;
  lineProps?: (lineNumber: number) => React.HTMLProps<HTMLElement>;
}
