import type { APIErrorResponse, PackerConfig } from "@/types/memshell";
import type { ProbeShellGenerateResponse, ProbeShellResult } from "@/types/probeshell";

import { useQuery } from "@tanstack/react-query";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import MainConfigPanel from "@/components/probeshell/main-config-panel";
import ShellResult from "@/components/probeshell/shell-result";
import { Button } from "@/components/ui/button";
import { env } from "@/config";
import { siteConfig } from "@/lib/config";
import { baseOptions } from "@/lib/layout.shared";
import {
  type ProbeShellFormSchema,
  probeShellFormSchema,
  useYupValidationProbeResolver,
} from "@/types/schema";
import { fetchJson } from "@/utils/fetch-json";
import { transformToProbePostData } from "@/utils/transformer";

export default function ProbeShellGenerator() {
  const serversQuery = useQuery<string[]>({
    queryKey: ["probeResponseServers"],
    queryFn: () => fetchJson<string[]>(`${env.API_URL}/api/config/probe/response/servers`),
  });

  const packerConfigQuery = useQuery<PackerConfig>({
    queryKey: ["packerConfig"],
    queryFn: () => fetchJson<PackerConfig>(`${env.API_URL}/api/config/packers/tree`),
  });

  const { data: responseServers } = serversQuery;
  const { data: packerConfig } = packerConfigQuery;

  const { t } = useTranslation(["common", "probeshell"]);

  const form = useForm<ProbeShellFormSchema>({
    resolver: useYupValidationProbeResolver(probeShellFormSchema, t),
    defaultValues: {
      probeMethod: "ResponseBody",
      probeContent: "Command",
      host: "",
      server: "Unknown",
      reqParamName: "",
      seconds: 5,
      sleepServer: "Tomcat",
      debug: false,
      byPassJavaModule: false,
      lambdaSuffix: false,
      shrink: true,
      staticInitialize: true,
    },
  });

  const [packResult, setPackResult] = useState<string | undefined>();
  const [generateResult, setGenerateResult] = useState<ProbeShellResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const submitLockRef = useRef(false);

  const onSubmit = async (data: ProbeShellFormSchema) => {
    if (submitLockRef.current) return;
    submitLockRef.current = true;

    try {
      const postData = transformToProbePostData(data);
      const response = await fetch(`${env.API_URL}/api/probe/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(postData),
      });

      if (!response.ok) {
        const json: APIErrorResponse = await response.json();
        toast.error(t("toast.generateError", { error: json.error }));
        return;
      }

      const result = (await response.json()) as ProbeShellGenerateResponse;
      setGenerateResult(result.probeShellResult);
      setPackResult(result.packResult);
      setPackMethod(data.packingMethod);
      toast.success(t("toast.generateSuccess"));
    } catch (error) {
      toast.error(t("toast.generateError", { error: (error as Error).message }));
    } finally {
      submitLockRef.current = false;
    }
  };
  return (
    <HomeLayout {...baseOptions()} links={siteConfig.navLinks}>
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
                  form={form}
                  responseServers={responseServers}
                  serversError={responseServers === undefined ? serversQuery.error : null}
                  isServersRetrying={serversQuery.isFetching}
                  onRetryServers={() => void serversQuery.refetch()}
                  packerConfig={packerConfig}
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
                {t("probeshell:buttons.generate")}
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
