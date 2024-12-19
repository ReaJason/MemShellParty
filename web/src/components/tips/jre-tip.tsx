import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { InfoIcon } from "lucide-react";

export function JRETip() {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoIcon className="cursor-pointer h-3" />
        </TooltipTrigger>
        <TooltipContent>
          <p>目标 JRE 版本，一般而言为了最大的兼容性，默认 Java 6 即可。</p>
          <p>特定情况下，例如 JDK8 才能使用 lambda 表达式，JDK9 以上存在模块限制时才需要选择特定的版本。</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
