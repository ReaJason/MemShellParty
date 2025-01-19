import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { InfoIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

export function UrlPatternTip() {
  const { t } = useTranslation();
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoIcon className="cursor-pointer h-4" />
        </TooltipTrigger>
        <TooltipContent>
          <p>{t("tips.servletUrlPattern")}</p>
          <p>{t("tips.controllerUrlPattern")}</p>
          <p>{t("tips.handlerUrlPattern")}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
