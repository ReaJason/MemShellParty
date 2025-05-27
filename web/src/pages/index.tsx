import { MainConfigCard } from "@/components/main-config-card.tsx";
import { PackageConfigCard } from "@/components/package-config-card.tsx";
import { ShellResult } from "@/components/shell-result.tsx";
import { Button } from "@/components/ui/button";
import { Form } from "@/components/ui/form.tsx";
import { env } from "@/config.ts";
import { FormSchema, formSchema } from "@/types/schema.ts";
import {
  APIErrorResponse,
  GenerateResponse,
  GenerateResult,
  MainConfig,
  PackerConfig,
  ServerConfig,
  ShellToolType,
} from "@/types/shell.ts";
import { customValidation, transformToPostData } from "@/utils/transformer.ts";
import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useLoaderData } from "react-router-dom";
import { toast } from "sonner";

export default function IndexPage() {
  const urlParams = useLoaderData();

  const { data: serverConfig } = useQuery<ServerConfig>({
    queryKey: ["serverConfig"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/config/servers`);
      return await response.json();
    },
  });

  const { data: mainConfig } = useQuery<MainConfig>({
    queryKey: ["mainConfig"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/config`);
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
  const form = useForm<FormSchema>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      server: urlParams.server ?? "Tomcat",
      targetJdkVersion: urlParams.targetJdkVersion ?? "50",
      debug: urlParams.debug ?? false,
      bypassJavaModule: urlParams.bypassJavaModule ?? false,
      shellClassName: urlParams.shellClassName ?? "",
      shellTool: urlParams.shellTool ?? ShellToolType.Godzilla,
      shellType: urlParams.shellType ?? "Listener",
      urlPattern: urlParams.urlPattern ?? "/*",
      godzillaPass: urlParams.godzillaPass ?? "",
      godzillaKey: urlParams.godzillaKey ?? "",
      commandParamName: urlParams.commandParamName ?? "",
      behinderPass: urlParams.behinderPass ?? "",
      antSwordPass: urlParams.antSwordPass ?? "",
      headerName: urlParams.headerName ?? "User-Agent",
      headerValue: urlParams.headerValue ?? "",
      injectorClassName: urlParams.injectorClassName ?? "",
      packingMethod: urlParams.packingMethod ?? "",
      shrink: urlParams.shrink ?? true,
      shellClassBase64: urlParams.shellClassBase64 ?? "",
    },
  });

  const [packResult, setPackResult] = useState<string | undefined>();
  const [allPackResults, setAllPackResults] = useState<Map<string, string> | undefined>();
  const [generateResult, setGenerateResult] = useState<GenerateResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const [isActionPending, startTransition] = useTransition();

  const onSubmit = async (data: FormSchema) => {
    startTransition(async () => {
      try {
        customValidation(t, data);
        const postData = transformToPostData(data);
        const response = await fetch(`${env.API_URL}/generate`, {
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

        const result = (await response.json()) as GenerateResponse;
        setGenerateResult(result.generateResult);
        setPackResult(result.packResult);
        setAllPackResults(result.allPackResults);
        setPackMethod(data.packingMethod);
        toast.success(t("success.generated"));
      } catch (error) {
        toast.error(t("errors.generationFailed", { error: (error as Error).message }));
      }
    });
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col xl:flex-row gap-4 p-4">
        <div className="w-full xl:w-1/2 space-y-4">
          <MainConfigCard servers={serverConfig} mainConfig={mainConfig} form={form} />
          <PackageConfigCard packerConfig={packerConfig} form={form} />
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
