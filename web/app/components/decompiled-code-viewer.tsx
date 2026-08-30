import type { TokenLine } from "@/lib/decompile/decompile.worker";

import { memo, type ReactNode } from "react";

import { CopyMenuButton, type CopyOption } from "@/components/code-viewer";

/** material-dark palette (react-syntax-highlighter prism theme) */
const TOKEN_COLORS: Record<string, string> = {
  atrule: "#c792ea",
  boolean: "#c792ea",
  builtin: "#ffcb6b",
  char: "#80cbc4",
  "class-name": "#f2ff00",
  comment: "#616161",
  constant: "#c792ea",
  function: "#c792ea",
  keyword: "#c792ea",
  number: "#fd9170",
  operator: "#89ddff",
  property: "#80cbc4",
  punctuation: "#89ddff",
  regex: "#f2ff00",
  string: "#a5e844",
  variable: "#ff6666",
};

const BACKGROUND = "#2f2f2f";
const PLAIN = "#eee";
const GUTTER_COLOR = "#616161";
const FONT_FAMILY = "Roboto Mono, monospace";

interface DecompiledCodeViewerProps {
  lines: TokenLine[] | null;
  placeholder: string;
  header?: ReactNode;
  button?: ReactNode;
  height: number;
  copyLabel: string;
  copyOptions: CopyOption[];
}

export default memo(function DecompiledCodeViewer({
  lines,
  placeholder,
  header,
  button,
  height,
  copyLabel,
  copyOptions,
}: Readonly<DecompiledCodeViewerProps>) {
  return (
    <div className="rounded-lg border">
      <div
        className={
          header
            ? "flex items-center justify-between border-b p-2"
            : "flex items-center justify-end border-b p-2"
        }
      >
        {header}
        <div className="flex items-center gap-2">
          {button}
          <CopyMenuButton
            options={copyOptions}
            variant="ghost"
            size="sm"
            aria-label={copyLabel}
            title={copyLabel}
          />
        </div>
      </div>
      <div
        className="overflow-auto text-xs"
        style={{
          height,
          background: BACKGROUND,
          color: PLAIN,
          borderRadius: "0 0 var(--radius) var(--radius)",
        }}
      >
        {lines ? (
          <div
            className="flex"
            style={{ fontFamily: FONT_FAMILY, lineHeight: "1.5em", tabSize: 4 }}
          >
            <div
              aria-hidden
              className="sticky left-0 shrink-0 pr-4 pl-4 text-right select-none"
              style={{ background: BACKGROUND, color: GUTTER_COLOR }}
            >
              {lines.map((_, index) => (
                <div key={index}>{index + 1}</div>
              ))}
            </div>
            <pre className="m-0 flex-1 pr-4" style={{ fontFamily: "inherit", tabSize: 4 }}>
              {lines.map((line, index) => (
                <div key={index} style={{ whiteSpace: "pre" }}>
                  {line.map(([type, text], segmentIndex) =>
                    type === "plain" ? (
                      text
                    ) : (
                      <span key={segmentIndex} style={{ color: TOKEN_COLORS[type] ?? PLAIN }}>
                        {text}
                      </span>
                    ),
                  )}
                  {line.length === 0 ? " " : null}
                </div>
              ))}
            </pre>
          </div>
        ) : (
          <pre
            className="m-0 p-4"
            style={{ fontFamily: FONT_FAMILY, lineHeight: "1.5em", whiteSpace: "pre-wrap" }}
          >
            {placeholder}
          </pre>
        )}
      </div>
    </div>
  );
});
