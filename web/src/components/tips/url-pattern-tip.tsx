import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { InfoIcon } from "lucide-react";

export function UrlPatternTip() {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoIcon className="cursor-pointer h-4" />
        </TooltipTrigger>
        <TooltipContent>
          <p>当使用 Servlet 内存马时必须写具体的 urlPattern，不能使用 /*，不然无法使用</p>
          <p>当使用 SpringMVC ControllerHandler 内存马时必须写具体的 urlPattern，不能使用 /*，不然无法使用</p>
          <p>当使用 SpringWebFlux HandlerMethod 内存马时必须写具体的 urlPattern，不能使用 /*，不然无法使用</p>
          <p>当使用 SpringWebFlux HandlerFunction 内存马时必须写具体的 urlPattern，不能使用 /*，不然无法使用</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
