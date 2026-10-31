import type {
  BytecodeClassResponse,
  BytecodeFormValues,
  BytecodeResult,
  BytecodeTransformResponse,
} from "@/types/bytecode";
import type { APIErrorResponse, PackerConfig } from "@/types/memshell";

import { useQuery } from "@tanstack/react-query";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import { LoaderCircle, WandSparklesIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { BytecodeConfigPanel } from "@/components/bytecode/config-panel";
import { BytecodeResultPanel } from "@/components/bytecode/result-panel";
import { Button } from "@/components/ui/button";
import { env } from "@/config";
import { siteConfig } from "@/lib/config";
import { fetchJson } from "@/utils/fetch-json";
import { buildObfuscation } from "@/utils/transformer";

import { baseOptions } from "../lib/layout.shared";

const homeLayoutOptions = baseOptions();
const decodeEndpoint = `${env.API_URL}/api/bytecode/decode`;
const transformEndpoint = `${env.API_URL}/api/bytecode/transform`;

const defaultValues: BytecodeFormValues = {
  inputMode: "base64",
  classBase64: "",
  fileClassBase64: "",
  fileName: "",
  packer: "",
  byPassJavaModule: false,
  staticInitialize: false,
  shrink: true,
  renamePackage: false,
  relocateFrom: "",
  relocateTo: "",
  entryMethodEnabled: false,
  entryMethod: "",
  newClassName: "",
  randomName: true,
  obfuscation: false,
  obfuscationOptions: "",
  probe: false,
  probeMethod: "ResponseBody",
  respHeaderName: "",
  server: "Unknown",
};

async function responseError(response: Response) {
  try {
    const body = (await response.json()) as APIErrorResponse;
    if (body.error) return body.error;
  } catch {
    // Fall back to the HTTP status when the response is not the API error shape.
  }
  return `${response.status} ${response.statusText}`.trim();
}

export default function BytecodeToolsPage() {
  const { t } = useTranslation("bytecode");
  const form = useForm<BytecodeFormValues>({ defaultValues });
  const inputMode = useWatch({ control: form.control, name: "inputMode" });
  const classBase64 = useWatch({ control: form.control, name: "classBase64" });
  const fileClassBase64 = useWatch({ control: form.control, name: "fileClassBase64" });
  const source = inputMode === "base64" ? classBase64 : fileClassBase64;

  const packerConfigQuery = useQuery<PackerConfig>({
    queryKey: ["packerConfig"],
    queryFn: () => fetchJson<PackerConfig>(`${env.API_URL}/api/config/packers/tree`),
  });

  const serversQuery = useQuery<string[]>({
    queryKey: ["probeResponseServers"],
    queryFn: () => fetchJson<string[]>(`${env.API_URL}/api/config/probe/response/servers`),
  });

  const [input, setInput] = useState<BytecodeClassResponse | undefined>();
  const [result, setResult] = useState<BytecodeResult | undefined>();
  const [isParsing, setIsParsing] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("original");
  const decodedSourceRef = useRef("");
  const decodeGenerationRef = useRef(0);
  const transformAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const generation = ++decodeGenerationRef.current;
    decodedSourceRef.current = "";
    setInput(undefined);
    form.setValue("newClassName", "");
    setParseError(null);
    setActiveTab("original");
    if (!source.trim()) {
      setIsParsing(false);
      return;
    }

    const controller = new AbortController();
    setIsParsing(true);
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch(decodeEndpoint, {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: source,
            signal: controller.signal,
          });
          if (!response.ok) throw new Error(await responseError(response));
          const decoded = (await response.json()) as BytecodeClassResponse;
          if (generation !== decodeGenerationRef.current) return;
          decodedSourceRef.current = source;
          setInput(decoded);
          form.setValue("newClassName", decoded.className);
          form.setValue("randomName", false);
        } catch (error) {
          if (generation !== decodeGenerationRef.current || controller.signal.aborted) return;
          setParseError(error instanceof Error ? error.message : String(error));
        } finally {
          if (generation === decodeGenerationRef.current) setIsParsing(false);
        }
      })();
    }, 400);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [form, source]);

  useEffect(
    () => () => {
      transformAbortRef.current?.abort();
    },
    [],
  );

  const onSubmit = async (values: BytecodeFormValues) => {
    if (!input || decodedSourceRef.current !== source) {
      toast.warning(t("input.required"));
      return;
    }

    transformAbortRef.current?.abort();
    const controller = new AbortController();
    transformAbortRef.current = controller;

    try {
      const response = await fetch(transformEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          classBytesBase64: input.classBytesBase64Str,
          packer: values.packer,
          byPassJavaModule: values.byPassJavaModule,
          staticInitialize: values.staticInitialize,
          shrink: values.shrink,
          renamePackage: values.renamePackage,
          relocateFrom: values.relocateFrom,
          relocateTo: values.relocateTo,
          entryMethod: values.entryMethodEnabled ? values.entryMethod : "",
          newClassName: values.newClassName,
          randomName: values.randomName,
          obfuscation: buildObfuscation(values.obfuscation, values.obfuscationOptions),
          server: values.server,
          probe: values.probe
            ? {
                probeMethod: values.probeMethod,
                probeContent: "Bytecode",
                respHeaderName:
                  values.probeMethod === "ResponseHeader" ? values.respHeaderName : undefined,
              }
            : undefined,
        }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(await responseError(response));
      const transformed = (await response.json()) as BytecodeTransformResponse;
      if (controller.signal.aborted) return;
      setResult({ ...transformed, packMethod: values.packer });
      setActiveTab("transformed");
    } catch (error) {
      if (controller.signal.aborted) return;
      toast.error(
        t("toast.convertError", { error: error instanceof Error ? error.message : String(error) }),
      );
    }
  };

  return (
    <HomeLayout {...homeLayoutOptions} links={siteConfig.navLinks}>
      <div className="max-w-8xl container mx-auto p-6 xl:flex xl:h-[calc(100dvh-3.5rem)] xl:flex-col">
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="grid grid-cols-1 gap-6 xl:min-h-0 xl:flex-1 xl:grid-cols-3 xl:grid-rows-1 xl:gap-x-4"
        >
          <div className="flex min-w-0 flex-col xl:min-h-0 xl:border-r">
            <div className="xl:-ml-2 xl:min-h-0 xl:overflow-y-auto xl:overscroll-contain xl:pl-2">
              <div className="xl:pr-4 xl:pb-2">
                <BytecodeConfigPanel
                  form={form}
                  packerConfig={packerConfigQuery.data}
                  packerError={
                    packerConfigQuery.data === undefined ? packerConfigQuery.error : null
                  }
                  isPackerRetrying={packerConfigQuery.isFetching}
                  onRetryPacker={() => void packerConfigQuery.refetch()}
                  responseServers={serversQuery.data}
                  serversError={serversQuery.data === undefined ? serversQuery.error : null}
                  isServersRetrying={serversQuery.isFetching}
                  onRetryServers={() => void serversQuery.refetch()}
                />
              </div>
            </div>
            <div className="shrink-0 pt-4 xl:pr-4">
              <Button
                className="w-full"
                type="submit"
                disabled={form.formState.isSubmitting || isParsing || !input}
              >
                {form.formState.isSubmitting ? (
                  <LoaderCircle className="animate-spin" />
                ) : (
                  <WandSparklesIcon />
                )}
                {t("convert")}
              </Button>
            </div>
          </div>
          <div className="flex min-w-0 flex-col gap-2 xl:col-span-2 xl:min-h-0 xl:overflow-y-auto xl:overscroll-contain xl:pr-1 xl:pb-6">
            <BytecodeResultPanel
              input={input}
              result={result}
              isParsing={isParsing}
              parseError={parseError}
              activeTab={activeTab}
              onTabChange={setActiveTab}
            />
          </div>
        </form>
      </div>
    </HomeLayout>
  );
}
