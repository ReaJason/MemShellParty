import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "../ui/alert-dialog";
import { CircleHelpIcon } from "lucide-react";
import { useTranslation } from "react-i18next";
import { AlertDialogFooter, AlertDialogHeader } from "../ui/alert-dialog";
import { Button } from "../ui/button";

export function FeedbackAlert() {
  const { t } = useTranslation();
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" type="button">
          <CircleHelpIcon /> {t("shellNotWork.title")}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t("shellNotWork.title")}</AlertDialogTitle>
          <AlertDialogDescription>
            <ol>
              <li>{t("shellNotWork.step1")}</li>
              <li>{t("shellNotWork.step2")}</li>
            </ol>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
          <AlertDialogAction
            onClick={() =>
              window.open(
                "https://github.com/ReaJason/MemShellParty/issues/new?template=%E5%86%85%E5%AD%98%E9%A9%AC%E7%94%9F%E6%88%90-bug-%E4%B8%8A%E6%8A%A5.md",
              )
            }
          >
            {t("feedback")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
