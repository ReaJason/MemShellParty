import type { VariantProps } from "class-variance-authority";

import { Check, Copy } from "lucide-react";
import { type HTMLProps, type ReactNode, useCallback, useEffect, useState } from "react";
import CopyToClipboard from "react-copy-to-clipboard";
import { useTranslation } from "react-i18next";
import { PrismLight as SyntaxHighlighter } from "react-syntax-highlighter";
import java from "react-syntax-highlighter/dist/esm/languages/prism/java";
import materialDark from "react-syntax-highlighter/dist/esm/styles/prism/material-dark";
import { toast } from "sonner";

import { Button, type buttonVariants } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

SyntaxHighlighter.registerLanguage("java", java);

/**
 * Small-screen height for the result viewers so pack/shell/injector panels line up.
 * Desktop result layouts use fillHeight to subtract the actual connection-info height.
 */
export const RESULT_VIEWER_HEIGHT = "clamp(256px, calc(100dvh - 33rem - 2px), 720px)";

interface CopyButtonProps extends React.ComponentProps<"button"> {
  value: string;
  src?: string;
  /** 复制成功后触发（用于「已使用」自动标记等场景） */
  onCopy?: () => void;
}

export interface CopyOption {
  label: string;
  value: string;
  disabled?: boolean;
  /** 该选项复制成功后触发 */
  onCopy?: () => void;
}

export function CopyButton({
  value,
  className,
  onCopy,
  ...buttonProps
}: Readonly<CopyButtonProps & VariantProps<typeof buttonVariants>>) {
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
      toast.success(t("copySuccess"), { duration: 1000 });
      onCopy?.();
    }
  }, [hasCopied, onCopy, t]);

  return (
    <CopyToClipboard.CopyToClipboard text={value} onCopy={handleCopy}>
      <Button
        {...buttonProps}
        variant="ghost"
        size="icon"
        type="button"
        className={cn("h-7 w-7 [&_svg]:h-4 [&_svg]:w-4", className)}
        disabled={hasCopied || buttonProps.disabled}
      >
        {hasCopied ? <Check /> : <Copy />}
      </Button>
    </CopyToClipboard.CopyToClipboard>
  );
}

export function CopyMenuButton({
  options,
  className,
  ...buttonProps
}: Readonly<
  { options: CopyOption[] } & React.ComponentProps<"button"> & VariantProps<typeof buttonVariants>
>) {
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
      toast.success(t("copySuccess"), { duration: 1000 });
    }
  }, [hasCopied, t]);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            {...buttonProps}
            variant="ghost"
            size="icon"
            type="button"
            className={cn("h-7 w-7 [&_svg]:h-4 [&_svg]:w-4", className)}
          />
        }
      >
        {hasCopied ? <Check /> : <Copy />}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {options.map((option) => (
          <CopyToClipboard.CopyToClipboard
            key={option.label}
            text={option.value}
            onCopy={() => {
              handleCopy();
              option.onCopy?.();
            }}
          >
            <DropdownMenuItem disabled={option.disabled}>{option.label}</DropdownMenuItem>
          </CopyToClipboard.CopyToClipboard>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export default function CodeViewer({
  code,
  header,
  button,
  language,
  height,
  fillHeight = false,
  showLineNumbers = true,
  wrapLongLines = true,
  copyLabel,
  copyDisabled = false,
  copyOptions,
  onCopy,
}: Readonly<CodeViewerProps>) {
  const lineProps: lineTagPropsFunction | HTMLProps<HTMLElement> | undefined = wrapLongLines
    ? { style: { overflowWrap: "break-word", whiteSpace: "pre-wrap" } }
    : undefined;
  return (
    <div
      className={cn("rounded-lg border", fillHeight && "xl:flex xl:h-full xl:min-h-0 xl:flex-col")}
    >
      <div
        className={cn(
          "flex shrink-0 items-center justify-end border-b p-2",
          header && "justify-between",
        )}
      >
        {header}
        <div className="flex items-center gap-2">
          {button}
          {copyOptions ? (
            <CopyMenuButton
              options={copyOptions}
              variant="ghost"
              size="sm"
              aria-label={copyLabel}
              title={copyLabel}
            />
          ) : (
            <CopyButton
              value={code}
              variant="ghost"
              size="sm"
              aria-label={copyLabel}
              title={copyLabel}
              disabled={copyDisabled}
              onCopy={onCopy}
            />
          )}
        </div>
      </div>
      <div
        className={cn(
          "wrap-all relative overflow-hidden text-xs",
          fillHeight && "xl:min-h-0 xl:flex-1",
        )}
      >
        <SyntaxHighlighter
          className={fillHeight ? "xl:h-full!" : undefined}
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
  /** 桌面双栏下填满结果面板剩余高度，小屏幕仍使用 height。 */
  fillHeight?: boolean;
  showLineNumbers?: boolean;
  wrapLongLines?: boolean;
  lineProps?: (lineNumber: number) => React.HTMLProps<HTMLElement>;
  copyLabel?: string;
  copyDisabled?: boolean;
  copyOptions?: CopyOption[];
  /** 复制 code 本体成功后触发（copyOptions 场景请在选项上单独设置 onCopy） */
  onCopy?: () => void;
}
