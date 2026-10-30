import type * as React from "react";

import { cn } from "@/lib/utils";

function SwitchFieldsPanel({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="switch-fields-panel"
      className={cn(
        "rounded-xl border border-border/70 bg-muted/50 p-3 text-[13px] shadow-[inset_0_1px_0_#fff,0_1px_2px_#0000000b] dark:bg-muted/20 dark:shadow-[inset_0_1px_0_#ffffff0a,0_1px_2px_#00000040]",
        "[&_[data-slot=collapsible-trigger]]:text-[13px] [&_[data-slot=field-label]]:text-[13px]",
        "[&_[data-slot=field-description]]:text-xs [&_[data-slot=field-error]]:text-xs",
        "[&_[data-slot=input]]:bg-background [&_[data-slot=input]]:text-[13px] [&_[data-slot=input]]:shadow-[0_2px_5px_#0000000b] [&_[data-slot=select-trigger]]:bg-background [&_[data-slot=select-trigger]]:text-[13px] [&_[data-slot=select-trigger]]:shadow-[0_2px_5px_#0000000b] [&_[data-slot=textarea]]:bg-background [&_[data-slot=textarea]]:text-[13px] [&_[data-slot=textarea]]:shadow-[0_2px_5px_#0000000b]",
        "dark:[&_[data-slot=input]]:bg-input/30 dark:[&_[data-slot=select-trigger]]:bg-input/30 dark:[&_[data-slot=textarea]]:bg-input/30",
        className,
      )}
      {...props}
    />
  );
}

export { SwitchFieldsPanel };
