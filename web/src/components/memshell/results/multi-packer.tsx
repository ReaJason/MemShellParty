import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import CodeViewer from "@/components/code-viewer";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function MultiPackResult({
  allPackResults,
  packMethod,
}: Readonly<{
  allPackResults: object | undefined;
  packMethod: string;
}>) {
  const showCode = packMethod === "JSP";
  const { t } = useTranslation();
  const packMethods = Object.keys(allPackResults ?? {});
  const [selectedMethod, setSelectedMethod] = useState(packMethods[0]);
  const [packResult, setPackResult] = useState(
    allPackResults?.[selectedMethod as keyof typeof allPackResults] ?? "",
  );

  useEffect(() => {
    const methods = Object.keys(allPackResults ?? {});
    const firstMethod = methods[0];
    setSelectedMethod(firstMethod);
    setPackResult(
      allPackResults?.[firstMethod as keyof typeof allPackResults] ?? "",
    );
  }, [allPackResults]);

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
      wrapLongLines={!showCode}
      showLineNumbers={showCode}
      language={showCode ? "java" : "text"}
      height={350}
    />
  );
}
