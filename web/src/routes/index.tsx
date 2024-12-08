import { MainConfigCard } from "@/components/main-config-card.tsx";
import { PackageConfigCard } from "@/components/package-config-card.tsx";
import { ShellConfigCard } from "@/components/shell-config-card.tsx";
import { ShellResult } from "@/components/shell-result.tsx";
import { Button } from "@/components/ui/button";
import { createFileRoute } from "@tanstack/react-router";
import { WandSparklesIcon } from "lucide-react";

export const Route = createFileRoute("/")({
  component: AboutComponent,
});

function AboutComponent() {
  return (
    <div className="flex flex-col md:flex-row gap-4 p-4">
      <div className="w-full md:w-1/2 space-y-4">
        <MainConfigCard />
        <ShellConfigCard />
        <PackageConfigCard />
        <Button className="w-full">
          <WandSparklesIcon />
          Generate
        </Button>
      </div>
      <div className="w-full md:w-1/2 space-y-4">
        <ShellResult />
      </div>
    </div>
  );
}
