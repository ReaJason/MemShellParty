import {
  ArrowUpRightIcon,
  AxeIcon,
  CommandIcon,
  NetworkIcon,
  ServerIcon,
  ShieldOffIcon,
  SwordIcon,
  WaypointsIcon,
  ZapIcon,
} from "lucide-react";
import { type JSX, useCallback, useEffect, useState } from "react";
import { FormProvider, type UseFormReturn } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { AntSwordTabContent } from "@/components/memshell/tabs/antsword-tab";
import { BehinderTabContent } from "@/components/memshell/tabs/behinder-tab";
import { CommandTabContent } from "@/components/memshell/tabs/command-tab";
import CustomTabContent from "@/components/memshell/tabs/custom-tab";
import { GodzillaTabContent } from "@/components/memshell/tabs/godzilla-tab";
import { NeoRegTabContent } from "@/components/memshell/tabs/neoreg-tab";
import { Suo5TabContent } from "@/components/memshell/tabs/suo5-tab";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.tsx";
import {
  FormControl,
  FormDescription,
  FormField,
  FormFieldItem,
  FormFieldLabel,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form.tsx";
import { Label } from "@/components/ui/label.tsx";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select.tsx";
import { Switch } from "@/components/ui/switch.tsx";
import { Tabs } from "@/components/ui/tabs";
import {
  type MainConfig,
  type ServerConfig,
  ShellToolType,
} from "@/types/memshell";
import type { MemShellFormSchema } from "@/types/schema.ts";

const shellToolIcons: Record<ShellToolType, JSX.Element> = {
  [ShellToolType.Behinder]: <ShieldOffIcon className="h-4 w-4" />,
  [ShellToolType.Godzilla]: <AxeIcon className="h-4 w-4" />,
  [ShellToolType.Command]: <CommandIcon className="h-4 w-4" />,
  [ShellToolType.AntSword]: <SwordIcon className="h-4 w-4" />,
  [ShellToolType.Suo5]: <WaypointsIcon className="h-4 w-4" />,
  [ShellToolType.NeoreGeorg]: <NetworkIcon className="h-4 w-4" />,
  [ShellToolType.Custom]: <ZapIcon className="h-4 w-4" />,
};

const defaultServerVersionOptions = [
  {
    name: "Unknown",
    value: "unknown",
  },
];

export default function MainConfigCard({
  mainConfig,
  form,
  servers,
}: Readonly<{
  mainConfig: MainConfig | undefined;
  form: UseFormReturn<MemShellFormSchema>;
  servers?: ServerConfig;
}>) {
  const [shellToolMap, setShellToolMap] = useState<{
    [toolName: string]: string[];
  }>();
  const [shellTools, setShellTools] = useState<ShellToolType[]>([
    ShellToolType.Godzilla,
    ShellToolType.Behinder,
    ShellToolType.AntSword,
    ShellToolType.Command,
    ShellToolType.Suo5,
    ShellToolType.NeoreGeorg,
    ShellToolType.Custom,
  ]);
  const [shellTypes, setShellTypes] = useState<string[]>([]);
  const shellTool = form.watch("shellTool");
  const { t } = useTranslation(["common", "memshell"]);

  const [serverVersionOptions, setServerVersionOptions] = useState(
    defaultServerVersionOptions,
  );

  // 处理一下 shellTypes 由于 server 或 shellTool 变更时无法正常为 form.shellType 赋值的问题
  useEffect(() => {
    if (shellTypes.length > 0) {
      form.setValue("shellType", shellTypes[0]);
    }
  }, [shellTypes, form]);

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

        // 特殊环境的 JDK 版本
        if (
          (value === "SpringWebFlux" || value === "XXLJOB") &&
          Number.parseInt(form.getValues("targetJdkVersion") as string, 10) < 52
        ) {
          form.setValue("targetJdkVersion", "52");
        } else {
          form.setValue("targetJdkVersion", "50");
        }

        // 特殊的服务需要指定版本
        if (value === "TongWeb") {
          setServerVersionOptions([
            ...defaultServerVersionOptions,
            {
              name: "6",
              value: "6",
            },
            {
              name: "7",
              value: "7",
            },
            {
              name: "8",
              value: "8",
            },
          ]);
        } else {
          setServerVersionOptions(defaultServerVersionOptions);
        }

        form.resetField("serverVersion");
        form.resetField("byPassJavaModule");
        form.resetField("urlPattern");
      }
    },
    [form, mainConfig],
  );

  // 处理一下默认值 server 不刷新 shellType 的问题
  useEffect(() => {
    if (mainConfig) {
      const initialServer = form.getValues("server");
      if (initialServer && mainConfig[initialServer]) {
        handleServerChange(initialServer);
      }
    }
  }, [mainConfig, form, handleServerChange]);

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

  return (
    <FormProvider {...form}>
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="text-md flex items-center gap-2">
            <ServerIcon className="h-5" />
            <span>{t("common:mainConfig.title")}</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <FormField
              control={form.control}
              name="server"
              render={({ field }) => (
                <FormFieldItem>
                  <FormFieldLabel>{t("common:server")}</FormFieldLabel>
                  <Select
                    onValueChange={(v) => {
                      field.onChange(v);
                      handleServerChange(v);
                    }}
                    value={field.value}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue
                          placeholder={t("common:placeholders.select")}
                        />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {Object.keys(servers ?? {}).map((server: string) => (
                        <SelectItem key={server} value={server}>
                          {server}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormDescription className="flex items-center">
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
                  </FormDescription>
                </FormFieldItem>
              )}
            />
            <FormField
              control={form.control}
              name="serverVersion"
              render={({ field }) => (
                <FormFieldItem>
                  <FormFieldLabel>{t("common:serverVersion")}</FormFieldLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue
                          placeholder={t("common:placeholders.select")}
                        />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {serverVersionOptions.map((v) => (
                        <SelectItem key={v.value} value={v.value}>
                          {v.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormFieldItem>
              )}
            />
          </div>
          <div className="flex gap-4 mt-4 flex-col sm:flex-row">
            <FormField
              control={form.control}
              name="debug"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      id="debug"
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel htmlFor="debug">{t("common:debug")}</FormLabel>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="byPassJavaModule"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2  space-y-0">
                  <FormControl>
                    <Switch
                      id="bypass"
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <Label htmlFor="bypass">{t("common:byPassJavaModule")}</Label>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="shrink"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      id="shrink"
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <Label htmlFor="shrink">{t("common:shrink")}</Label>
                </FormItem>
              )}
            />
          </div>
        </CardContent>
      </Card>
      <Tabs value={shellTool} className="w-full">
        <FormField
          control={form.control}
          name="shellTool"
          render={({ field }) => (
            <FormItem>
              <Select
                value={field.value}
                onValueChange={(v) => handleShellToolChange(v)}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
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
            </FormItem>
          )}
        />

        <GodzillaTabContent form={form} shellTypes={shellTypes} />
        <CommandTabContent form={form} shellTypes={shellTypes} />
        <BehinderTabContent form={form} shellTypes={shellTypes} />
        <AntSwordTabContent form={form} shellTypes={shellTypes} />
        <Suo5TabContent form={form} shellTypes={shellTypes} />
        <NeoRegTabContent form={form} shellTypes={shellTypes} />
        <CustomTabContent form={form} shellTypes={shellTypes} />
      </Tabs>
    </FormProvider>
  );
}
