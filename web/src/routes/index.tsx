import { MainConfigCard } from "@/components/main-config-card.tsx";
import { PackageConfigCard } from "@/components/package-config-card.tsx";
import { ShellResult } from "@/components/shell-result.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button";
import { Form } from "@/components/ui/form.tsx";
import { env } from "@/config.ts";
import { FormSchema, formSchema } from "@/types/schema.ts";
import { APIErrorResponse, ConfigResponseType, GenerateResponse, GenerateResult } from "@/types/shell.ts";
import { transformToPostData } from "@/utils/transformer.ts";
import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { ActivityIcon, LoaderCircle, ServerOffIcon, WandSparklesIcon } from "lucide-react";
import { useState, useTransition } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";

export const Route = createFileRoute("/")({
  component: IndexComponent,
});

function IndexComponent() {
  const { isPending, isError, data } = useQuery<ConfigResponseType>({
    queryKey: ["config"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/config`);
      return await response.json();
    },
  });
  const form = useForm<FormSchema>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      server: "",
      targetJdkVersion: "50",
      debug: false,
      bypassJavaModule: false,
      shellClassName: "",
      shellTool: "",
      shellType: "",
      urlPattern: "/*",
      godzillaPass: "pass",
      godzillaKey: "key",
      godzillaHeaderName: "User-Agent",
      godzillaHeaderValue: "test",
      commandParamName: "cmd",
      behinderPass: "pass",
      behinderHeaderName: "User-Agent",
      behinderHeaderValue: "test",
      injectorClassName: "",
      packingMethod: "Base64",
    },
  });

  const [packResult, setPackResult] = useState<string>("// 等待填写参数生成中");
  const [generateResult, setGenerateResult] = useState<GenerateResult>();
  const [packMethod, setPackMethod] = useState<string>("");
  const [isActionPending, startTransition] = useTransition();

  async function onSubmit(values: FormSchema) {
    startTransition(async () => {
      if (values.shellType.endsWith("Servlet") && (values.urlPattern === "/*" || !values.urlPattern)) {
        toast.warning("Servlet 类型的需要填写具体的 URL Pattern，例如 /hello_servlet");
        return;
      }

      if (values.shellType.endsWith("ControllerHandler") && (values.urlPattern === "/*" || !values.urlPattern)) {
        toast.warning("ControllerHandler 类型的需要填写具体的 URL Pattern，例如 /hello_controller");
        return;
      }

      const postData = transformToPostData(values);
      try {
        const response = await fetch(`${env.API_URL}/generate`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(postData),
        });
        await new Promise((resolve) => setTimeout(resolve, 500));
        if (response.ok) {
          const json: GenerateResponse = await response.json();
          setPackResult(json.packResult);
          setGenerateResult(json.generateResult);
          setPackMethod(values.packingMethod);
          toast.success("生成成功");
        } else {
          const json: APIErrorResponse = await response.json();
          toast.error(`生成失败，${json.error}`);
        }
      } catch (err) {
        const error = err as Error;
        toast.error(`生成失败，${error.message}`);
      }
    });
  }

  return (
    <div className="mt-4">
      <div className="px-4">
        {isPending && (
          <Alert>
            <LoaderCircle className="animate-spin h-4 w-4" />
            <AlertTitle>Pending</AlertTitle>
            <AlertDescription>正在全力搜索可用的后端服务~</AlertDescription>
          </Alert>
        )}
        {isError && (
          <Alert variant="destructive">
            <ServerOffIcon className="h-4 w-4" />
            <AlertTitle>Not Work!</AlertTitle>
            <AlertDescription>未检测到可用后端服务，生成功能暂不可用.</AlertDescription>
          </Alert>
        )}

        {!isError && data && (
          <Alert>
            <ActivityIcon className="h-4 w-4" />
            <AlertTitle>It Work!</AlertTitle>
            <AlertDescription>Let's start the party! 🎉</AlertDescription>
          </Alert>
        )}
      </div>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col xl:flex-row gap-4 p-4">
          <div className="w-full xl:w-1/2 space-y-2">
            <MainConfigCard servers={data?.servers} mainConfig={data?.core} form={form} />
            <PackageConfigCard packerConfig={data?.packers} form={form} />
            <Button className="w-full" type="submit" disabled={isActionPending}>
              {isActionPending ? <LoaderCircle className="animate-spin" /> : <WandSparklesIcon />}
              Generate
            </Button>
          </div>
          <div className="w-full xl:w-1/2 space-y-4">
            <ShellResult packMethod={packMethod} generateResult={generateResult} packResult={packResult} />
          </div>
        </form>
      </Form>
    </div>
  );
}
