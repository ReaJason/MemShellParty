import { motion } from "framer-motion";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { ArrowRight, ListChecks, Plug, Radar, WandSparkles } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { CopyButton } from "@/components/code-viewer";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { env } from "@/config";
import { siteConfig } from "@/lib/config";
import { baseOptions } from "@/lib/layout.shared";

const apiBase = (env.API_URL ?? "").replace(/\/+$/, "");

/**
 * 构建期预渲染没有 window，先按环境变量给出相对/绝对地址；
 * 客户端挂载后再用当前 origin 补齐，避免水合不一致。
 */
function resolveMcpUrl(origin?: string): string {
  if (/^https?:\/\//.test(apiBase)) return `${apiBase}/mcp`;
  return origin ? `${origin}${apiBase}/mcp` : `${apiBase}/mcp`;
}

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.12 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
};

function CodeBlock({
  code,
  copyLabel,
  wrap = false,
}: {
  code: string;
  copyLabel: string;
  wrap?: boolean;
}) {
  return (
    <div className="group/code relative rounded-lg border bg-muted/40 transition-colors hover:border-foreground/20">
      <pre
        className={
          wrap
            ? "overflow-x-auto p-4 pr-12 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap"
            : "overflow-x-auto p-4 pr-12 font-mono text-xs leading-relaxed"
        }
      >
        <code>{code}</code>
      </pre>
      <CopyButton
        value={code}
        aria-label={copyLabel}
        title={copyLabel}
        className="absolute top-2 right-2 opacity-0 transition-opacity group-hover/code:opacity-100 focus:opacity-100"
      />
    </div>
  );
}

export default function McpPage() {
  const { t } = useTranslation(["mcp", "common"]);
  const [mcpUrl, setMcpUrl] = useState(() => resolveMcpUrl());
  const copyLabel = t("common:copy");

  useEffect(() => {
    setMcpUrl(resolveMcpUrl(window.location.origin));
  }, []);

  const tools = [
    {
      name: "memshell_capabilities",
      icon: <ListChecks className="size-5" aria-hidden="true" />,
      description: t("tools.capabilities.description"),
      recommended: true,
    },
    {
      name: "generate_memshell",
      icon: <WandSparkles className="size-5" aria-hidden="true" />,
      description: t("tools.memshell.description"),
    },
    {
      name: "generate_probe_shell",
      icon: <Radar className="size-5" aria-hidden="true" />,
      description: t("tools.probe.description"),
    },
  ];

  const claudeCodeCommand = `claude mcp add --transport http memshell-party ${mcpUrl}`;
  const cursorConfig = JSON.stringify(
    { mcpServers: { "memshell-party": { type: "streamableHttp", url: mcpUrl } } },
    null,
    2,
  );
  const vscodeConfig = JSON.stringify(
    { servers: { "memshell-party": { type: "http", url: mcpUrl } } },
    null,
    2,
  );
  const desktopConfig = JSON.stringify(
    { mcpServers: { "memshell-party": { command: "npx", args: ["mcp-remote", mcpUrl] } } },
    null,
    2,
  );

  const steps = [t("workflow.step1"), t("workflow.step2"), t("workflow.step3")];

  return (
    <HomeLayout {...baseOptions()} links={siteConfig.navLinks}>
      {/* Hero header */}
      <section className="relative overflow-hidden border-b py-12">
        <div className="bg-grid-black/[0.03] dark:bg-grid-white/[0.03] pointer-events-none absolute inset-0 [mask-image:linear-gradient(to_bottom,white_30%,transparent_100%)]" />
        <motion.div
          initial={{ opacity: 0, y: -30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="relative z-10 container mx-auto max-w-5xl space-y-4 px-4"
        >
          <Badge variant="outline">Streamable HTTP</Badge>
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl">{t("title")}</h1>

          {/* Endpoint inline */}
          <div className="flex max-w-2xl items-center gap-2 rounded-lg border bg-background/80 px-4 py-3 backdrop-blur">
            <Plug className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <code className="min-w-0 flex-1 overflow-x-auto font-mono text-sm whitespace-nowrap">
              {mcpUrl}
            </code>
            <CopyButton value={mcpUrl} aria-label={copyLabel} title={copyLabel} />
          </div>
          <p className="text-xs text-muted-foreground">{t("endpoint.hint")}</p>
        </motion.div>
      </section>

      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="container mx-auto max-w-5xl space-y-10 px-4 py-10"
      >
        {/* Tools */}
        <motion.section variants={itemVariants} className="space-y-4">
          <h2 className="text-lg font-semibold">{t("tools.title")}</h2>
          <div className="grid gap-4 md:grid-cols-3">
            {tools.map((tool) => (
              <Card key={tool.name} className="group transition-shadow hover:shadow-md" size="sm">
                <CardHeader className="pt-0">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <span className="flex size-7 items-center justify-center rounded-md bg-muted text-muted-foreground transition-colors group-hover:bg-accent group-hover:text-accent-foreground">
                      {tool.icon}
                    </span>
                    <code className="font-mono break-all">{tool.name}</code>
                  </CardTitle>
                  {tool.recommended && <Badge variant="secondary">{t("tools.callFirst")}</Badge>}
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  {tool.description}
                </CardContent>
              </Card>
            ))}
          </div>
        </motion.section>

        {/* Client configs */}
        <motion.section variants={itemVariants} className="space-y-4">
          <h2 className="text-lg font-semibold">{t("clients.title")}</h2>
          <Tabs defaultValue="claude-code">
            <TabsList className="max-w-full overflow-x-auto">
              <TabsTrigger value="claude-code">Claude Code</TabsTrigger>
              <TabsTrigger value="cursor">Cursor</TabsTrigger>
              <TabsTrigger value="vscode">VS Code</TabsTrigger>
              <TabsTrigger value="desktop">Claude Desktop</TabsTrigger>
            </TabsList>
            <TabsContent value="claude-code">
              <CodeBlock code={claudeCodeCommand} copyLabel={copyLabel} />
            </TabsContent>
            <TabsContent value="cursor" className="space-y-2">
              <CodeBlock code={cursorConfig} copyLabel={copyLabel} />
              <p className="text-xs text-muted-foreground">{t("clients.cursorHint")}</p>
            </TabsContent>
            <TabsContent value="vscode" className="space-y-2">
              <CodeBlock code={vscodeConfig} copyLabel={copyLabel} />
              <p className="text-xs text-muted-foreground">{t("clients.vscodeHint")}</p>
            </TabsContent>
            <TabsContent value="desktop" className="space-y-2">
              <p className="text-xs text-muted-foreground">{t("clients.desktopHint")}</p>
              <CodeBlock code={desktopConfig} copyLabel={copyLabel} />
            </TabsContent>
          </Tabs>
          <p className="text-xs text-muted-foreground">{t("clients.restartHint")}</p>
        </motion.section>

        {/* Workflow — visual timeline steps */}
        <motion.section variants={itemVariants} className="space-y-4">
          <h2 className="text-lg font-semibold">{t("workflow.title")}</h2>
          <ol
            className="relative space-y-0 border-l-2 border-border"
            aria-label={t("workflow.title")}
          >
            {steps.map((text, i) => (
              <li key={i} className="relative flex items-start gap-4 py-4 pl-8">
                <span className="absolute -left-[calc(0.875rem+1px)] flex size-7 items-center justify-center rounded-full border-2 border-border bg-background text-xs font-semibold text-foreground">
                  {i + 1}
                </span>
                <span className="text-sm text-muted-foreground">{text}</span>
              </li>
            ))}
          </ol>

          <div className="flex items-start gap-3 rounded-lg border border-dashed bg-muted/30 p-4">
            <ArrowRight
              className="mt-0.5 size-4 shrink-0 text-muted-foreground"
              aria-hidden="true"
            />
            <div className="min-w-0 flex-1 space-y-2">
              <p className="text-sm font-medium">{t("workflow.example")}</p>
              <CodeBlock code={t("workflow.examplePrompt")} copyLabel={copyLabel} wrap />
            </div>
          </div>
        </motion.section>
      </motion.div>
    </HomeLayout>
  );
}
