import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { useTranslation } from "react-i18next";

export function QuickUsage() {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("quickUsage.title")}</CardTitle>
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
