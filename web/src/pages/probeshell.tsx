import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import MainConfigCard from "@/components/probeshell/main-config-card";
import PackageConfigCard from "@/components/probeshell/package-config-card";
import ShellResult from "@/components/probeshell/shell-result";
import { Button } from "@/components/ui/button";
import {
  Form,
} from "@/components/ui/form";
import { env } from "@/config";
import type { APIErrorResponse, PackerConfig, ServerConfig } from "@/types/memshell";
import type { ProbeShellGenerateResponse, ProbeShellResult } from "@/types/probeshell";
import { type ProbeShellFormSchema, probeShellFormSchema, useYupValidationProbeResolver } from "@/types/schema";
import { transformToProbePostData } from "@/utils/transformer";

export default function ProbeShellGenerator() {
  const { data: serverConfig } = useQuery<ServerConfig>({
    queryKey: ["serverConfig"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/config/servers`);
      return await response.json();
    },
  });

  const { data: packerConfig } = useQuery<PackerConfig>({
    queryKey: ["packerConfig"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/config/packers`);
      return await response.json();
    },
  });

    const { t } = useTranslation();

  const form = useForm<ProbeShellFormSchema>({
    resolver: useYupValidationProbeResolver(probeShellFormSchema, t),
    defaultValues: {
      probeMethod: "Sleep",
      probeContent: "Server",
      host: "",
      server: "Tomcat",
      reqParamName: "payload",
      reqHeaderName: "X-PAYLOAD",
      seconds: 5,
      sleepServer: "Tomcat"
    },
  });

  const [packResult, setPackResult] = useState<string | undefined>();
  const [allPackResults, setAllPackResults] = useState<Map<string, string> | undefined>();
  const [generateResult, setGenerateResult] = useState<ProbeShellResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const [isActionPending, startTransition] = useTransition();

  const onSubmit = async (data: ProbeShellFormSchema) => {
      startTransition(async () => {
      try {
        const postData = transformToProbePostData(data);
        const response = await fetch(`${env.API_URL}/probe/generate`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(postData),
        });

        if (!response.ok) {
          const json: APIErrorResponse = await response.json();
          toast.error(t("errors.generationFailed", { error: json.error }));
          return;
        }

        const result = (await response.json()) as ProbeShellGenerateResponse;
        setGenerateResult(result.probeShellResult);
        setPackResult(result.packResult);
        setAllPackResults(result.allPackResults);
        setPackMethod(data.packingMethod);
        toast.success(t("success.generated"));
      } catch (error) {
        toast.error(t("errors.generationFailed", { error: (error as Error).message }));
      }
    });
  }
  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col xl:flex-row gap-4 p-4">
        <div className="w-full xl:w-1/2 space-y-4">
          <MainConfigCard form={form} servers={serverConfig} />
          <PackageConfigCard form={form} packerConfig={packerConfig} />
          <Button className="w-full" type="submit" disabled={isActionPending}>
            {isActionPending ? <LoaderCircle className="animate-spin" /> : <WandSparklesIcon />}
            {t("buttons.generate")}
          </Button>
        </div>
        <div className="w-full xl:w-1/2 space-y-4">
          <ShellResult
            packMethod={packMethod}
            generateResult={generateResult}
            packResult={packResult}
            allPackResults={allPackResults}
          />
        </div>
      </form>
    </Form>
  );
}
