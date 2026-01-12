import {
  ArrowUpRightIcon,
  AxeIcon,
  CommandIcon,
  InfoIcon,
  NetworkIcon,
  ServerIcon,
  ShieldOffIcon,
  SwordIcon,
  WaypointsIcon,
  ZapIcon,
} from "lucide-react";
import { type JSX, useCallback, useRef, useState } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { AntSwordTabContent } from "@/components/memshell/tabs/antsword-tab";
import { BehinderTabContent } from "@/components/memshell/tabs/behinder-tab";
import { CommandTabContent } from "@/components/memshell/tabs/command-tab";
import CustomTabContent from "@/components/memshell/tabs/custom-tab";
import { GodzillaTabContent } from "@/components/memshell/tabs/godzilla-tab";
import { NeoRegTabContent } from "@/components/memshell/tabs/neoreg-tab";
import { Suo5TabContent } from "@/components/memshell/tabs/suo5-tab";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "@/components/ui/field";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  type MainConfig,
  type ServerConfig,
  ShellToolType,
} from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema";
import { Spinner } from "../ui/spinner";

const JDKVersion = [
  { name: "Java6", value: "50" },
  { name: "Java8", value: "52" },
  { name: "Java9", value: "53" },
  { name: "Java11", value: "55" },
  { name: "Java17", value: "61" },
  { name: "Java21", value: "65" },
];

const shellToolIcons: Record<ShellToolType, JSX.Element> = {
  [ShellToolType.Behinder]: <ShieldOffIcon className="h-4 w-4" />,
  [ShellToolType.Godzilla]: <AxeIcon className="h-4 w-4" />,
  [ShellToolType.Command]: <CommandIcon className="h-4 w-4" />,
  [ShellToolType.AntSword]: <SwordIcon className="h-4 w-4" />,
  [ShellToolType.Suo5]: <WaypointsIcon className="h-4 w-4" />,
  [ShellToolType.Suo5v2]: <WaypointsIcon className="h-4 w-4" />,
  [ShellToolType.NeoreGeorg]: <NetworkIcon className="h-4 w-4" />,
  [ShellToolType.Custom]: <ZapIcon className="h-4 w-4" />,
};

export default function MainConfigCard({
  mainConfig,
  form,
  servers,
}: Readonly<{
  mainConfig: MainConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
  servers?: ServerConfig;
}>) {
  const { t } = useTranslation(["common", "memshell"]);

  const [shellToolMap, setShellToolMap] = useState<{
    [toolName: string]: string[];
  }>();
  const [shellTools, setShellTools] = useState<ShellToolType[]>([]);
  const [shellTypes, setShellTypes] = useState<string[]>([]);

  const shellTool = useWatch({
    control: form.control,
    name: "shellTool",
  });

  const handleServerChange = useCallback(
    (value: string) => {
      if (mainConfig) {
        const newShellToolMap = mainConfig[value];
        setShellToolMap(newShellToolMap);

        const newShellTools = Object.keys(newShellToolMap);
        setShellTools([
          ...newShellTools.map((tool) => tool as ShellToolType),
          ShellToolType.Custom,
        ]);

        const currentShellTool = form.getValues("shellTool");

        const firstTool = newShellTools[0];
        let currentShellTypes = null;

        if (!newShellToolMap[currentShellTool]) {
          form.setValue("shellTool", firstTool);
          currentShellTypes = newShellToolMap[firstTool];
        } else {
          currentShellTypes = newShellToolMap[currentShellTool];
        }
        setShellTypes(currentShellTypes);

        if (currentShellTypes && currentShellTypes.length > 0) {
          form.setValue("shellType", currentShellTypes[0]);
        }

        if (
          (value === "SpringWebFlux" || value === "XXLJOB") &&
          Number.parseInt(form.getValues("targetJdkVersion") as string, 10) < 52
        ) {
          form.setValue("targetJdkVersion", "52");
        } else {
          form.setValue("targetJdkVersion", "50");
        }

        form.resetField("serverVersion");
        form.resetField("byPassJavaModule");
        form.resetField("urlPattern");
      }
    },
    [form, mainConfig],
  );

  const handleShellToolChange = useCallback(
    (value: string) => {
      const resetCommand = () => {
        form.resetField("commandParamName");
        form.resetField("implementationClass");
        form.resetField("encryptor");
      };

      const resetGodzilla = () => {
        form.resetField("godzillaKey");
        form.resetField("godzillaPass");
        form.resetField("headerName");
        form.resetField("headerValue");
      };

      const resetBehinder = () => {
        form.resetField("behinderPass");
        form.resetField("headerName");
        form.resetField("headerValue");
      };

      const resetSuo5 = () => {
        form.resetField("headerName");
        form.resetField("headerValue");
      };

      const resetAntSword = () => {
        form.resetField("antSwordPass");
        form.resetField("headerName");
        form.resetField("headerValue");
      };

      const resetNeoreGeorg = () => {
        form.setValue("headerName", "Referer");
        form.resetField("headerValue");
      };

      const resetCustom = () => {
        form.resetField("shellClassBase64");
      };

      if (shellToolMap) {
        let currentShellTypes = null;
        if (value === ShellToolType.Custom) {
          currentShellTypes = servers?.[form.getValues("server")] as string[];
        } else {
          currentShellTypes = shellToolMap[value];
        }
        setShellTypes(currentShellTypes);

        // 直接设置 shellType 而不是依赖 useEffect
        if (currentShellTypes && currentShellTypes.length > 0) {
          form.setValue("shellType", currentShellTypes[0]);
        }

        form.resetField("urlPattern");
        form.resetField("shellClassName");
        form.resetField("injectorClassName");
        if (value === ShellToolType.Godzilla) {
          resetGodzilla();
        } else if (value === ShellToolType.Behinder) {
          resetBehinder();
        } else if (value === ShellToolType.Command) {
          resetCommand();
        } else if (value === ShellToolType.Suo5) {
          resetSuo5();
        } else if (value === ShellToolType.AntSword) {
          resetAntSword();
        } else if (value === ShellToolType.NeoreGeorg) {
          resetNeoreGeorg();
        } else if (value === ShellToolType.Custom) {
          resetCustom();
        }
      }
      form.setValue("shellTool", value);
    },
    [form, servers, shellToolMap],
  );

  const initializedRef = useRef(false);
  if (!initializedRef.current && mainConfig) {
    const initialServer = form.getValues("server");
    if (initialServer && mainConfig[initialServer]) {
      handleServerChange(initialServer);
      initializedRef.current = true;
    }
  }

  return (
    <>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-md flex items-center gap-2">
            <ServerIcon className="h-5" />
            <span>{t("common:mainConfig.title")}</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!mainConfig ? (
            <div className="flex items-center justify-center p-4 gap-4 h-100">
              <Spinner />
              <span className="text-sm text-muted-foreground">
                {t("loading")}
              </span>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <Controller
                  control={form.control}
                  name="server"
                  render={({ field }) => (
                    <Field>
                      <FieldContent>
                        <FieldLabel htmlFor="server">
                          {t("common:server")}
                        </FieldLabel>
                        <Select
                          onValueChange={(v) => {
                            field.onChange(v);
                            handleServerChange(v as string);
                          }}
                          value={field.value}
                        >
                          <SelectTrigger id="server">
                            <SelectValue
                              data-placeholder={t("common:placeholders.select")}
                            />
                          </SelectTrigger>
                          <SelectContent>
                            {Object.keys(servers ?? {}).map(
                              (server: string) => (
                                <SelectItem key={server} value={server}>
                                  {server}
                                </SelectItem>
                              ),
                            )}
                          </SelectContent>
                        </Select>
                        <FieldDescription className="flex items-center">
                          {t("memshell:tips.targetServerNotFound")}&nbsp;
                          <a
                            href="https://github.com/ReaJason/MemShellParty/issues/new?template=%E8%AF%B7%E6%B1%82%E9%80%82%E9%85%8D.md"
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center underline"
                          >
                            {t("memshell:tips.targetServerRequest")}
                            <ArrowUpRightIcon className="h-4" />
                          </a>
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  )}
                />
                <Controller
                  control={form.control}
                  name="targetJdkVersion"
                  render={({ field, fieldState }) => (
                    <Field
                      orientation="vertical"
                      data-invalid={fieldState.invalid}
                    >
                      <FieldContent>
                        <FieldLabel htmlFor="targetJdkVersion">
                          {t("common:targetJdkVersion")}
                        </FieldLabel>
                        <Select
                          onValueChange={(v) => {
                            if (Number.parseInt(v ?? "0", 10) >= 53) {
                              form.setValue("byPassJavaModule", true);
                            } else {
                              form.setValue("byPassJavaModule", false);
                            }
                            field.onChange(v);
                          }}
                          value={field.value}
                        >
                          <SelectTrigger
                            id="targetJdkVersion"
                            aria-invalid={fieldState.invalid}
                          >
                            <SelectValue
                              data-placeholder={t("common:placeholders.select")}
                            />
                          </SelectTrigger>
                          <SelectContent>
                            {JDKVersion.map((v) => (
                              <SelectItem key={v.value} value={v.value}>
                                {v.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        {fieldState.error && (
                          <FieldError errors={[fieldState.error]} />
                        )}
                      </FieldContent>
                    </Field>
                  )}
                />
              </div>
              <div className="grid grid-cols-1">
                <Controller
                  control={form.control}
                  name="shellTool"
                  render={({ field }) => (
                    <Field>
                      <FieldContent>
                        <FieldLabel htmlFor="shellTool">
                          {t("common:shellTool")}
                        </FieldLabel>
                        <Select
                          value={field.value}
                          onValueChange={(v) =>
                            handleShellToolChange(v as string)
                          }
                        >
                          <SelectTrigger id="shellTool">
                            <SelectValue
                              data-placeholder={t("common:placeholders.select")}
                            />
                          </SelectTrigger>
                          <SelectContent>
                            {shellTools.map((tool) => (
                              <SelectItem key={tool} value={tool}>
                                <span className="flex items-center gap-2">
                                  {shellToolIcons[tool]}
                                  {tool}
                                </span>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </FieldContent>
                    </Field>
                  )}
                />
              </div>
              <div className="flex gap-4 mt-4 flex-col lg:grid lg:grid-cols-2 2xl:grid 2xl:grid-cols-3">
                <Controller
                  control={form.control}
                  name="debug"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="debug"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                      <Label htmlFor="debug">{t("common:debug")}</Label>
                      <Tooltip>
                        <TooltipTrigger>
                          <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:debug.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  )}
                />
                <Controller
                  control={form.control}
                  name="probe"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="probe"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                      <Label htmlFor="probe">{t("common:probe")}</Label>
                      <Tooltip>
                        <TooltipTrigger>
                          <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:probe.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  )}
                />
                <Controller
                  control={form.control}
                  name="byPassJavaModule"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="bypass"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                      <Label htmlFor="bypass">
                        {t("common:byPassJavaModule")}
                      </Label>
                      <Tooltip>
                        <TooltipTrigger>
                          <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:byPassJavaModule.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  )}
                />
                <Controller
                  control={form.control}
                  name="lambdaSuffix"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="lambdaSuffix"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                      <Label htmlFor="lambdaSuffix">
                        {t("common:lambdaSuffix")}
                      </Label>
                      <Tooltip>
                        <TooltipTrigger>
                          <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:lambdaSuffix.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  )}
                />
                <Controller
                  control={form.control}
                  name="shrink"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="shrink"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                      <Label htmlFor="shrink">{t("common:shrink")}</Label>
                      <Tooltip>
                        <TooltipTrigger>
                          <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:shrink.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  )}
                />
                <Controller
                  control={form.control}
                  name="staticInitialize"
                  render={({ field }) => (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="staticInitialize"
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                      <Label htmlFor="staticInitialize">
                        {t("common:staticInitialize")}
                      </Label>
                      <Tooltip>
                        <TooltipTrigger>
                          <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{t("common:staticInitialize.description")}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                  )}
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      {mainConfig && (
        <Tabs value={shellTool} className="w-full">
          <GodzillaTabContent form={form} shellTypes={shellTypes} />
          <CommandTabContent form={form} shellTypes={shellTypes} />
          <BehinderTabContent form={form} shellTypes={shellTypes} />
          <AntSwordTabContent form={form} shellTypes={shellTypes} />
          <Suo5TabContent tabValue="Suo5" form={form} shellTypes={shellTypes} />
          <Suo5TabContent
            tabValue="Suo5v2"
            form={form}
            shellTypes={shellTypes}
          />
          <NeoRegTabContent form={form} shellTypes={shellTypes} />
          <CustomTabContent form={form} shellTypes={shellTypes} />
        </Tabs>
      )}
    </>
  );
}
