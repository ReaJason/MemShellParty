import type {VariantProps} from "class-variance-authority";
import {Check, Copy} from "lucide-react";
import {type HTMLProps, type ReactNode, useCallback, useEffect, useState} from "react";
import {CopyToClipboard} from "react-copy-to-clipboard";
import {useTranslation} from "react-i18next";
import {PrismLight as SyntaxHighlighter} from "react-syntax-highlighter";
import java from "react-syntax-highlighter/dist/esm/languages/prism/java";
import {materialDark} from "react-syntax-highlighter/dist/esm/styles/prism";
import {toast} from "sonner";
import {Button, type buttonVariants} from "@/components/ui/button";
import {cn} from "@/lib/utils";

SyntaxHighlighter.registerLanguage("java", java);
interface CopyButtonProps extends React.ComponentProps<"button"> {
  value: string;
  src?: string;
}

export function CopyButton({ value }: Readonly<CopyButtonProps & VariantProps<typeof buttonVariants>>) {
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
      toast.success(t("copySuccess"), { duration: 1000 });
    }
  }, [hasCopied, t]);

  return (
    <CopyToClipboard text={value} onCopy={handleCopy}>
      <Button
        variant="ghost"
        size="icon"
        type="button"
        className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
        disabled={hasCopied}
      >
        {hasCopied ? <Check /> : <Copy />}
      </Button>
    </CopyToClipboard>
  );
}

export default function CodeViewer({
  code,
  header,
  button,
  language,
  height,
  showLineNumbers = true,
  wrapLongLines = true,
}: Readonly<CodeViewerProps>) {
  const lineProps: lineTagPropsFunction | HTMLProps<HTMLElement> | undefined = wrapLongLines
    ? { style: { overflowWrap: "break-word", whiteSpace: "pre-wrap" } }
    : undefined;
  return (
    <div className="rounded-lg border">
      <div className={cn("flex items-center border-b p-2 justify-end", header && "justify-between")}>
        {header}
        <div className="flex items-center gap-2">
          {button}
          <CopyButton value={code} variant="ghost" size="sm" />
        </div>
      </div>
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
  button?: ReactNode;
  height?: string | number;
  showLineNumbers?: boolean;
  wrapLongLines?: boolean;
  lineProps?: (lineNumber: number) => React.HTMLProps<HTMLElement>;
}
