import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function QuickUsage() {
  const { t } = useTranslation(["common", "probeshell"]);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-md flex items-center gap-2">
          <ScrollTextIcon className="h-5" />
          <span>{t("common:quickUsage.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal list-inside space-y-4 text-sm">
          <li>{t("probeshell:quickUsage.step1")}</li>
          <li>{t("probeshell:quickUsage.step2")}</li>
          <li>{t("probeshell:quickUsage.step3")}</li>
        </ol>
      </CardContent>
    </Card>
  );
}
