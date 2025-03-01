import { env } from "@/config";
import { useQuery } from "@tanstack/react-query";
import { CircleX, LoaderCircle, RefreshCcw } from "lucide-react";
import type React from "react";
import { useTranslation } from "react-i18next";
import { Button } from "./ui/button";
import { TooltipContent, TooltipTrigger } from "./ui/tooltip";
import { Tooltip } from "./ui/tooltip";
import { TooltipProvider } from "./ui/tooltip";
type VersionInfo = {
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
};

const VersionBadge: React.FC = () => {
  const { isPending, data, isError } = useQuery<VersionInfo>({
    queryKey: ["version"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/version`);
      if (response.ok) {
        return await response.json();
      }
      return "unknown";
    },
  });
  const inProduction = env.MODE === "production";
  const { t } = useTranslation();

  return (
    <div className="flex items-center space-x-2">
      {isPending && (
        <Button className="rounded-full" size="sm" variant="ghost">
          <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
        </Button>
      )}
      {isError && (
        <Button
          className="rounded-full"
          size="sm"
          variant="ghost"
          onClick={() => {
            window.open("https://github.com/ReaJason/MemShellParty/releases");
          }}
        >
          <CircleX className="h-3.5 w-3.5" />
        </Button>
      )}
      {data?.hasUpdate && inProduction && (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                className="rounded-full bg-yellow-500 text-white hover:bg-yellow-600 hover:text-white"
                size="sm"
                variant="ghost"
                onClick={() => {
                  window.open(`https://github.com/ReaJason/MemShellParty/releases/tag/v${data.latestVersion}`);
                }}
              >
                <span className="flex items-center gap-1">
                  <RefreshCcw className="h-3.5 w-3.5" />
                  {t("version.updateAvailable")}
                </span>
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>
                {t("version.updateAvailableTooltip", {
                  currentVersion: data.currentVersion,
                  latestVersion: data.latestVersion,
                })}
              </p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
      {data && (!data.hasUpdate || !inProduction) && (
        <Button
          className="rounded-full bg-green-500 text-white hover:bg-green-600 hover:text-white"
          size="sm"
          variant="ghost"
        >
          <span>v{data.currentVersion}</span>
        </Button>
      )}
    </div>
  );
};

export default VersionBadge;
