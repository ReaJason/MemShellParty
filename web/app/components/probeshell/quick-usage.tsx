import { useTranslation } from "react-i18next";

export function QuickUsage() {
  const { t } = useTranslation("probeshell");
  return (
    <ol className="flex list-inside list-decimal flex-col gap-4 text-sm">
      <li>{t("quickUsage.step1")}</li>
      <li>{t("quickUsage.step2")}</li>
      <li>{t("quickUsage.step3")}</li>
    </ol>
  );
}
