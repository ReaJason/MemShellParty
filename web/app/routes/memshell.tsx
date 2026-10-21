import { useQuery } from "@tanstack/react-query";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import MainConfigPanel from "@/components/memshell/main-config-panel";
import ShellResult from "@/components/memshell/shell-result";
import { Button } from "@/components/ui/button";
import { env } from "@/config";
import { siteConfig } from "@/lib/config";
import {
  type APIErrorResponse,
  type MainConfig,
  type MemShellGenerateResponse,
  type MemShellResult,
  type PackerConfig,
  type ShellToolConfigEntry,
  ShellToolType,
} from "@/types/memshell";
import {
  type MemShellFormSchema,
  memShellFormSchema,
  useYupValidationResolver,
} from "@/types/schema";
import { fetchJson } from "@/utils/fetch-json";
import { transformToPostData } from "@/utils/transformer";

import { baseOptions } from "../lib/layout.shared";

const homeLayoutOptions = baseOptions();

const defaultValues: MemShellFormSchema = {
  server: "Tomcat",
  serverVersion: "Unknown",
  targetJdkVersion: "50",
  debug: false,
  byPassJavaModule: false,
  shellClassName: "",
  shellTool: ShellToolType.Godzilla,
  shellType: "Listener",
  urlPattern: "/*",
  pass: "",
  key: "",
  paramName: "",
  template: "",
  headerName: "User-Agent",
  headerValue: "",
  injectorClassName: "",
  packingMethod: "",
  shrink: true,
  staticInitialize: true,
  shellClassBase64: "",
};

const jsonHeaders = {
  "Content-Type": "application/json",
} as const;

const fetchMainConfig = () => fetchJson<MainConfig>(`${env.API_URL}/api/config`);

const fetchPackerConfig = () => fetchJson<PackerConfig>(`${env.API_URL}/api/config/packers/tree`);

const fetchShellToolConfigs = () =>
  fetchJson<Array<ShellToolConfigEntry>>(`${env.API_URL}/api/config/shelltool/configs`);

export default function MemShellPage() {
  const mainConfigQuery = useQuery<MainConfig>({
    queryKey: ["mainConfig"],
    queryFn: fetchMainConfig,
  });

  const packerConfigQuery = useQuery<PackerConfig>({
    queryKey: ["packerConfig"],
    queryFn: fetchPackerConfig,
  });

  const shellToolConfigsQuery = useQuery<Array<ShellToolConfigEntry>>({
    queryKey: ["shellToolConfigs"],
    queryFn: fetchShellToolConfigs,
  });

  const { data: mainConfig } = mainConfigQuery;
  const { data: packerConfig } = packerConfigQuery;
  const { data: shellToolConfigs } = shellToolConfigsQuery;

  // 核心配置由两个接口共同决定，任一失败都算配置不可用；不能继续把它们当成「加载中」。
  // 已经有数据时忽略后台刷新失败，避免一次 refetch 抖动把可用表单换成错误页。
  const configError =
    (mainConfig === undefined ? mainConfigQuery.error : null) ??
    (shellToolConfigs === undefined ? shellToolConfigsQuery.error : null);
  const isConfigRetrying = mainConfigQuery.isFetching || shellToolConfigsQuery.isFetching;
  const retryConfig = () => {
    void mainConfigQuery.refetch();
    void shellToolConfigsQuery.refetch();
  };

  const { t } = useTranslation(["common", "memshell"]);
  const form = useForm<MemShellFormSchema>({
    resolver: useYupValidationResolver(memShellFormSchema, t),
    defaultValues,
  });

  const [packResult, setPackResult] = useState<string | undefined>();
  const [generateResult, setGenerateResult] = useState<MemShellResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const submitLockRef = useRef(false);

  const submitMemShell = useCallback(
    async (data: MemShellFormSchema) => {
      if (!shellToolConfigs?.some((config) => config.tool === data.shellTool)) {
        toast.error(t("memshell:tips.shellToolConfigUnavailable"));
        return;
      }
      try {
        const postData = transformToPostData(data, shellToolConfigs);
        const response = await fetch(`${env.API_URL}/api/memshell/generate`, {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify(postData),
        });

        if (!response.ok) {
          const json: APIErrorResponse = await response.json();
          toast.error(t("toast.generateError", { error: json.error }));
          return;
        }

        const result = (await response.json()) as MemShellGenerateResponse;
        setGenerateResult(result.memShellResult);
        setPackResult(result.packResult);
        setPackMethod(data.packingMethod);
        toast.success(t("toast.generateSuccess"));
      } catch (error) {
        toast.error(t("toast.generateError", { error: (error as Error).message }));
      }
    },
    [shellToolConfigs, t],
  );

  const onSubmit = useCallback(
    async (data: MemShellFormSchema) => {
      if (submitLockRef.current) return;
      submitLockRef.current = true;

      try {
        await submitMemShell(data);
      } finally {
        submitLockRef.current = false;
      }
    },
    [submitMemShell],
  );

  return (
    <HomeLayout {...homeLayoutOptions} links={siteConfig.navLinks}>
      <div className="max-w-8xl container mx-auto p-6 xl:flex xl:h-[calc(100dvh-3.5rem)] xl:flex-col">
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="grid grid-cols-1 gap-6 xl:min-h-0 xl:flex-1 xl:grid-cols-3 xl:grid-rows-1 xl:gap-x-4"
        >
          <div className="flex min-w-0 flex-col xl:min-h-0 xl:border-r">
            {/* 滚动区不撑满：内容放得下时按钮紧跟表单；超出时才收缩滚动区，把按钮压在底部 */}
            <div className="xl:-ml-2 xl:min-h-0 xl:overflow-y-auto xl:overscroll-contain xl:pl-2">
              <div className="xl:pr-4 xl:pb-2">
                <MainConfigPanel
                  mainConfig={mainConfig}
                  shellToolConfigs={shellToolConfigs}
                  packerConfig={packerConfig}
                  form={form}
                  configError={configError}
                  isConfigRetrying={isConfigRetrying}
                  onRetryConfig={retryConfig}
                  packerConfigError={packerConfig === undefined ? packerConfigQuery.error : null}
                  isPackerRetrying={packerConfigQuery.isFetching}
                  onRetryPacker={() => void packerConfigQuery.refetch()}
                />
              </div>
            </div>
            <div className="shrink-0 pt-4 xl:pr-4">
              <Button className="w-full" type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? (
                  <LoaderCircle className="animate-spin" />
                ) : (
                  <WandSparklesIcon />
                )}
                {t("memshell:buttons.generate")}
              </Button>
            </div>
          </div>
          <div className="flex min-w-0 flex-col gap-2 xl:col-span-2 xl:min-h-0 xl:overflow-y-auto xl:overscroll-contain xl:pr-1 xl:pb-6">
            <ShellResult
              packMethod={packMethod}
              generateResult={generateResult}
              packResult={packResult}
            />
          </div>
        </form>
      </div>
    </HomeLayout>
  );
}
