import { InfoIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip.tsx";

export function JreTip() {
  const { t } = useTranslation();
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoIcon className="cursor-pointer h-4" />
        </TooltipTrigger>
        <TooltipContent>
          <p>{t("tips.jreTip")}</p>
          <p>{t("tips.jreTip2")}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
