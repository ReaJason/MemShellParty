import { useQuery } from "@tanstack/react-query";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useCallback, useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import MainConfigCard from "@/components/memshell/main-config-card";
import PackageConfigCard from "@/components/memshell/package-config-card";
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
  type ServerConfig,
  ShellToolType,
} from "@/types/memshell";
import {
  type MemShellFormSchema,
  memShellFormSchema,
  useYupValidationResolver,
} from "@/types/schema";
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
  godzillaPass: "",
  godzillaKey: "",
  commandParamName: "",
  behinderPass: "",
  antSwordPass: "",
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

const fetchJson = async <T,>(url: string): Promise<T> => {
  const response = await fetch(url);
  return response.json() as Promise<T>;
};

const fetchServerConfig = () =>
  fetchJson<ServerConfig>(`${env.API_URL}/api/config/servers`);

const fetchMainConfig = () =>
  fetchJson<MainConfig>(`${env.API_URL}/api/config`);

const fetchPackerConfig = () =>
  fetchJson<PackerConfig>(`${env.API_URL}/api/config/packers`);

export default function MemShellPage() {
  const { data: serverConfig } = useQuery<ServerConfig>({
    queryKey: ["serverConfig"],
    queryFn: fetchServerConfig,
  });

  const { data: mainConfig } = useQuery<MainConfig>({
    queryKey: ["mainConfig"],
    queryFn: fetchMainConfig,
  });

  const { data: packerConfig } = useQuery<PackerConfig>({
    queryKey: ["packerConfig"],
    queryFn: fetchPackerConfig,
  });

  const { t } = useTranslation(["common", "memshell"]);
  const form = useForm({
    resolver: useYupValidationResolver(memShellFormSchema, t),
    defaultValues,
  });

  const [packResult, setPackResult] = useState<string | undefined>();
  const [allPackResults, setAllPackResults] = useState<
    Map<string, string> | undefined
  >();
  const [generateResult, setGenerateResult] = useState<MemShellResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const [isActionPending, startTransition] = useTransition();

  const submitMemShell = useCallback(
    async (data: MemShellFormSchema) => {
      try {
        const postData = transformToPostData(data);
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
        setAllPackResults(result.allPackResults);
        setPackMethod(data.packingMethod);
        toast.success(t("toast.generateSuccess"));
      } catch (error) {
        toast.error(
          t("toast.generateError", { error: (error as Error).message }),
        );
      }
    },
    [t],
  );

  const onSubmit = useCallback(
    (data: MemShellFormSchema) => {
      startTransition(() => {
        void submitMemShell(data);
      });
    },
    [submitMemShell],
  );

  return (
    <HomeLayout {...homeLayoutOptions} links={siteConfig.navLinks}>
      <div className="container mx-auto max-w-8xl p-6">
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="flex flex-col xl:flex-row gap-6"
        >
          <div className="w-full xl:w-1/2 flex flex-col gap-2">
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
          <div className="w-full xl:w-1/2 flex flex-col gap-2">
            <ShellResult
              packMethod={packMethod}
              generateResult={generateResult}
              packResult={packResult}
              allPackResults={allPackResults}
            />
          </div>
        </form>
      </div>
    </HomeLayout>
  );
}
