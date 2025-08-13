import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import commonEN from "@/i18n/common/en.json";
import commonZH from "@/i18n/common/zh-CN.json";
import memshellEN from "@/i18n/memshell/en.json";
import memshellZH from "@/i18n/memshell/zh-CN.json";
import probeshellEN from "@/i18n/probeshell/en.json";
import probeshellZH from "@/i18n/probeshell/zh-CN.json";

const getStoredLanguage = () => {
  const storedLang = localStorage.getItem("i18nextLng");
  if (storedLang && ["en", "zh-CN"].includes(storedLang)) {
    return storedLang;
  }
  const browserLang = navigator.language.split("-")[0];
  return ["en", "zh-CN"].includes(browserLang) ? browserLang : "en";
};

const fallbackLng = "en";
export const ns = [
  "default",
  "common",
  "memshell",
  "probeshell",
  "errors",
] as const;
export const defaultNS = "default" as const;

const resources = {
  "zh-CN": {
    common: commonZH,
    memshell: memshellZH,
    probeshell: probeshellZH,
  },
  en: {
    common: commonEN,
    memshell: memshellEN,
    probeshell: probeshellEN,
  },
};

i18n.use(initReactI18next).init({
  ns,
  defaultNS,
  resources,
  lng: getStoredLanguage(),
  fallbackLng,
  interpolation: {
    escapeValue: false,
  },
});

i18n.on("languageChanged", (lng) => {
  localStorage.setItem("i18nextLng", lng);
});

export default i18n;
