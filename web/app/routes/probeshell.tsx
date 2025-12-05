import { useQuery } from "@tanstack/react-query";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import MainConfigCard from "@/components/probeshell/main-config-card";
import PackageConfigCard from "@/components/probeshell/package-config-card";
import ShellResult from "@/components/probeshell/shell-result";
import { Button } from "@/components/ui/button";
import { Form } from "@/components/ui/form";
import { env } from "@/config";
import { siteConfig } from "@/lib/config";
import type {
  APIErrorResponse,
  PackerConfig,
  ServerConfig,
} from "@/types/memshell";
import type {
  ProbeShellGenerateResponse,
  ProbeShellResult,
} from "@/types/probeshell";
import {
  type ProbeShellFormSchema,
  probeShellFormSchema,
  useYupValidationProbeResolver,
} from "@/types/schema";
import { transformToProbePostData } from "@/utils/transformer";
import { baseOptions } from "../lib/layout.shared";

export default function ProbeShellGenerator() {
  const { data: serverConfig } = useQuery<ServerConfig>({
    queryKey: ["serverConfig"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/api/config/servers`);
      return await response.json();
    },
  });

  const { data: packerConfig } = useQuery<PackerConfig>({
    queryKey: ["packerConfig"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/api/config/packers`);
      return await response.json();
    },
  });

  const { t } = useTranslation(["common", "probeshell"]);

  const form = useForm<ProbeShellFormSchema>({
    resolver: useYupValidationProbeResolver(probeShellFormSchema, t),
    defaultValues: {
      probeMethod: "Sleep",
      probeContent: "Server",
      host: "",
      server: "Tomcat",
      reqParamName: "payload",
      seconds: 5,
      sleepServer: "Tomcat",
      shrink: true,
      staticInitialize: true,
    },
  });

  const [packResult, setPackResult] = useState<string | undefined>();
  const [allPackResults, setAllPackResults] = useState<
    Map<string, string> | undefined
  >();
  const [generateResult, setGenerateResult] = useState<ProbeShellResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const [isActionPending, startTransition] = useTransition();

  const onSubmit = async (data: ProbeShellFormSchema) => {
    startTransition(async () => {
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
        setAllPackResults(result.allPackResults);
        setPackMethod(data.packingMethod);
        toast.success(t("toast.generateSuccess"));
      } catch (error) {
        toast.error(
          t("toast.generateError", { error: (error as Error).message }),
        );
      }
    });
  };
  return (
    <HomeLayout {...baseOptions()} links={siteConfig.navLinks}>
      <div className="container mx-auto max-w-7xl p-4">
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit)}
            className="flex flex-col xl:flex-row gap-6"
          >
            <div className="w-full xl:w-1/2 flex flex-col gap-4">
              <MainConfigCard form={form} servers={serverConfig} />
              <PackageConfigCard form={form} packerConfig={packerConfig} />
              <Button
                className="w-full"
                type="submit"
                disabled={isActionPending}
              >
                {isActionPending ? (
                  <LoaderCircle className="animate-spin" />
                ) : (
                  <WandSparklesIcon />
                )}
                {t("probeshell:buttons.generate")}
              </Button>
            </div>
            <div className="w-full xl:w-1/2 flex flex-col gap-4">
              <ShellResult
                packMethod={packMethod}
                generateResult={generateResult}
                packResult={packResult}
                allPackResults={allPackResults}
              />
            </div>
          </form>
        </Form>
      </div>
    </HomeLayout>
  );
}
