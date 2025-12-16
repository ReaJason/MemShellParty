import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function QuickUsage() {
  const { t } = useTranslation(["common", "memshell"]);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ScrollTextIcon className="h-5" />
          <span>{t("common:quickUsage.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="flex flex-col gap-4 list-decimal list-inside text-sm">
          <li>{t("memshell:quickUsage.step1")}</li>
          <li>{t("memshell:quickUsage.step2")}</li>
          <li>{t("memshell:quickUsage.step3")}</li>
          <li>{t("memshell:quickUsage.step4")}</li>
          <li>{t("memshell:quickUsage.step5")}</li>
        </ol>
      </CardContent>
    </Card>
  );
}
