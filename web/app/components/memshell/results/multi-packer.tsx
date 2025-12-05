import { DownloadIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import CodeViewer from "@/components/code-viewer";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { base64ToBytes, downloadBytes, downloadContent } from "@/lib/utils";

export function MultiPackResult({
  allPackResults,
  packMethod,
  shellClassName,
  height = 350,
}: Readonly<{
  allPackResults: object | undefined;
  packMethod: string;
  shellClassName?: string;
  height?: number;
}>) {
  const showCode = packMethod === "JSP";
  const { t } = useTranslation();
  const packMethods = Object.keys(allPackResults ?? {});

  const [selectedMethod, setSelectedMethod] = useState(packMethods[0]);
  const [packResult, setPackResult] = useState(
    allPackResults?.[selectedMethod as keyof typeof allPackResults] ?? "",
  );

  useEffect(() => {
    const newPackMethods = Object.keys(allPackResults ?? {});
    if (!newPackMethods.includes(selectedMethod)) {
      const newSelectedMethod = newPackMethods[0];
      setSelectedMethod(newSelectedMethod);
      setPackResult(
        allPackResults?.[newSelectedMethod as keyof typeof allPackResults] ??
          "",
      );
    } else {
      setPackResult(
        allPackResults?.[selectedMethod as keyof typeof allPackResults] ?? "",
      );
    }
  }, [allPackResults, selectedMethod]);

  const handleDownload = () => {
    const fileName =
      shellClassName?.substring(shellClassName?.lastIndexOf(".") ?? 0) ?? "";
    if (packMethod === "JSP") {
      const fileExtension = selectedMethod.includes("JSPX") ? ".jspx" : ".jsp";
      const content = new Blob([packResult], { type: "text/plain" });
      return downloadContent(content, fileName, fileExtension);
    } else if (
      packMethod === "JavaDeserialize" ||
      packMethod.includes("Hessian")
    ) {
      const content = new Blob([base64ToBytes(packResult)], {
        type: "application/octet-stream",
      });
      return downloadContent(content, fileName, ".data");
    } else if (packMethod === "Base64") {
      const base64Content =
        allPackResults?.[
          Object.keys(allPackResults)[0] as keyof typeof allPackResults
        ] ?? "";
      return downloadBytes(base64Content, shellClassName);
    }
  };

  return (
    <CodeViewer
      code={packResult ?? ""}
      header={
        <div className="flex items-center justify-between text-xs gap-2">
          <Select
            onValueChange={(value) => {
              setSelectedMethod(value);
              setPackResult(
                allPackResults?.[value as keyof typeof allPackResults] ?? "",
              );
            }}
            value={selectedMethod}
          >
            <SelectTrigger className="h-7 text-xs [&_svg]:h-4 [&_svg]:w-4">
              <span className="text-muted-foreground">
                {t("common:packerMethod")}:&nbsp;
              </span>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {packMethods.map((method) => (
                <SelectItem key={method} value={method} className="text-xs">
                  {method}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="text-muted-foreground">({packResult?.length})</span>
        </div>
      }
      button={
        packMethod === "JSP" ||
        packMethod === "Base64" ||
        packMethod === "JavaDeserialize" ||
        packMethod.includes("Hessian") ? (
          <Button
            variant="ghost"
            size="icon"
            type="button"
            className="h-7 w-7 [&_svg]:h-4 [&_svg]:w-4"
            onClick={handleDownload}
          >
            <DownloadIcon className="h-4 w-4" />
          </Button>
        ) : null
      }
      wrapLongLines={!showCode}
      showLineNumbers={showCode}
      language={showCode ? "java" : "text"}
      height={height}
    />
  );
}
