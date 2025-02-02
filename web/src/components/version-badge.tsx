import { env } from "@/config";
import { useQuery } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import type React from "react";
import { Button } from "./ui/button";

const VersionBadge: React.FC = () => {
  const { isPending, data } = useQuery<string>({
    queryKey: ["version"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/version`);
      await new Promise((resolve) => setTimeout(resolve, 100));
      return await response.text();
    },
  });

  return (
    <div className="flex items-center space-x-2">
      <Button
        className={`rounded-full ${data && "bg-green-500 text-white"}`}
        size="sm"
        variant={isPending ? "ghost" : "default"}
      >
        {isPending ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <span>v{data}</span>}
      </Button>
    </div>
  );
};

export default VersionBadge;
