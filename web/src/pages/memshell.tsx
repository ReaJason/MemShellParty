import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useLoaderData } from "react-router-dom";
import { toast } from "sonner";
import MainConfigCard from "@/components/memshell/main-config-card";
import PackageConfigCard from "@/components/memshell/package-config-card";
import ShellResult from "@/components/memshell/shell-result";
import { Button } from "@/components/ui/button";
import { Form } from "@/components/ui/form.tsx";
import { env } from "@/config.ts";
import {
  type APIErrorResponse,
  type MainConfig,
  type MemShellGenerateResponse,
  type MemShellResult,
  type PackerConfig,
  type ServerConfig,
  ShellToolType,
} from "@/types/memshell";
import {
  type MemShellFormSchema,
  memShellFormSchema,
  useYupValidationResolver,
} from "@/types/schema.ts";
import { transformToPostData } from "@/utils/transformer.ts";

export default function MemShellPage() {
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

  const { t } = useTranslation(["common", "memshell"]);
  const form = useForm({
    resolver: useYupValidationResolver(memShellFormSchema, t),
    defaultValues: {
      server: urlParams.server ?? "Tomcat",
      serverVersion: urlParams.serverVersion ?? "unknown",
      targetJdkVersion: urlParams.targetJdkVersion ?? "50",
      debug: urlParams.debug ?? false,
      byPassJavaModule: urlParams.byPassJavaModule ?? false,
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
  const [allPackResults, setAllPackResults] = useState<
    Map<string, string> | undefined
  >();
  const [generateResult, setGenerateResult] = useState<MemShellResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const [isActionPending, startTransition] = useTransition();

  const onSubmit = async (data: MemShellFormSchema) => {
    startTransition(async () => {
      try {
        const postData = transformToPostData(data);
        const response = await fetch(`${env.API_URL}/memshell/generate`, {
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

        const result = (await response.json()) as MemShellGenerateResponse;
        setGenerateResult(result.memShellResult);
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
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className="flex flex-col xl:flex-row gap-4 p-4"
      >
        <div className="w-full xl:w-1/2 space-y-4">
          <MainConfigCard
            servers={serverConfig}
            mainConfig={mainConfig}
            form={form}
          />
          <PackageConfigCard packerConfig={packerConfig} form={form} />
          <Button className="w-full" type="submit" disabled={isActionPending}>
            {isActionPending ? (
              <LoaderCircle className="animate-spin" />
            ) : (
              <WandSparklesIcon />
            )}
            {t("memshell:buttons.generate")}
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
