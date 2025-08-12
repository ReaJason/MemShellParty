import { ScrollTextIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";

export function QuickUsage() {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-md flex items-center gap-2">
          <ScrollTextIcon className="h-5" />
          <span>{t("quickUsage.title")}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal list-inside space-y-4 text-sm">
          <li>{t("quickUsage.step1")}</li>
          <li>{t("quickUsage.step2")}</li>
          <li>{t("quickUsage.step3")}</li>
          <li>{t("quickUsage.step4")}</li>
          <li>{t("quickUsage.step5")}</li>
        </ol>
      </CardContent>
    </Card>
  );
}
