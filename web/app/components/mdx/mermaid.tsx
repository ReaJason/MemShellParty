"use client";

import { CodeBlock, Pre } from "fumadocs-ui/components/codeblock";
import { useEffect, useId, useState, useSyncExternalStore } from "react";

export function Mermaid({ chart }: { chart: string }) {
  // false on the server and during hydration
  const isClient = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false,
  );

  if (!isClient) return null;
  return <MermaidContent chart={chart} />;
}

type RenderResult = { svg: string; bindFunctions?: (element: Element) => void };

let mermaidPromise: Promise<typeof import("mermaid")> | undefined;

function loadMermaid() {
  return (mermaidPromise ??= import("mermaid"));
}

// observe <html> instead of the provider so the diagram follows the docs theme
function subscribeTheme(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributeFilter: ["class"] });
  return () => observer.disconnect();
}

// mermaid's own palette is purple; map the base theme to the neutral shadcn one
const lightThemeVariables = {
  background: "#ffffff",
  primaryColor: "#f5f5f5",
  primaryTextColor: "#171717",
  primaryBorderColor: "#d4d4d4",
  secondaryColor: "#fafafa",
  tertiaryColor: "#fafafa",
  textColor: "#404040",
  mainBkg: "#f5f5f5",
  nodeBorder: "#d4d4d4",
  clusterBkg: "#fafafa",
  clusterBorder: "#e5e5e5",
  edgeLabelBackground: "#ffffff",
  lineColor: "#737373",
  titleColor: "#171717",
  fontSize: "14px",
};

const darkThemeVariables = {
  background: "#0a0a0a",
  primaryColor: "#262626",
  primaryTextColor: "#fafafa",
  primaryBorderColor: "#404040",
  secondaryColor: "#171717",
  tertiaryColor: "#171717",
  textColor: "#d4d4d4",
  mainBkg: "#262626",
  nodeBorder: "#404040",
  clusterBkg: "#171717",
  clusterBorder: "#404040",
  edgeLabelBackground: "#0a0a0a",
  lineColor: "#a3a3a3",
  titleColor: "#fafafa",
  fontSize: "14px",
};

function MermaidContent({ chart }: { chart: string }) {
  const id = useId();
  const dark = useSyncExternalStore(
    subscribeTheme,
    () => document.documentElement.classList.contains("dark"),
    () => false,
  );
  // undefined while rendering, null when mermaid rejects the chart
  const [result, setResult] = useState<RenderResult | null>();

  useEffect(() => {
    let cancelled = false;
    setResult(undefined);

    loadMermaid()
      .then(({ default: mermaid }) => {
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "loose",
          fontFamily: "inherit",
          theme: "base",
          themeVariables: dark ? darkThemeVariables : lightThemeVariables,
          flowchart: { nodeSpacing: 28, rankSpacing: 32, padding: 8, wrappingWidth: 240 },
        });

        const renderId = `mermaid-${id.replace(/[^a-zA-Z0-9_-]/g, "")}`;
        return mermaid.render(renderId, chart.replaceAll("\\n", "\n"));
      })
      .then((rendered) => {
        if (!cancelled) setResult(rendered);
      })
      .catch(() => {
        if (!cancelled) setResult(null);
      });

    return () => {
      cancelled = true;
    };
  }, [chart, dark, id]);

  if (result === undefined) return <div className="mermaid-diagram min-h-24" aria-busy="true" />;

  if (result === null) {
    return (
      <CodeBlock title="Mermaid">
        <Pre>{chart}</Pre>
      </CodeBlock>
    );
  }

  return (
    <div
      className="mermaid-diagram overflow-x-auto"
      role="img"
      aria-label="流程图"
      ref={(container) => {
        if (container) result.bindFunctions?.(container);
      }}
      dangerouslySetInnerHTML={{ __html: result.svg }}
    />
  );
}
