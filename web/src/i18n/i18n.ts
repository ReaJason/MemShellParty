import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { resources } from "./translations";

const getStoredLanguage = () => {
  const storedLang = localStorage.getItem("i18nextLng");
  if (storedLang && ["en", "zh"].includes(storedLang)) {
    return storedLang;
  }
  const browserLang = navigator.language.split("-")[0];
  return ["en", "zh"].includes(browserLang) ? browserLang : "en";
};

i18n.use(initReactI18next).init({
  resources,
  lng: getStoredLanguage(),
  fallbackLng: "en",
  interpolation: {
    escapeValue: false,
  },
  detection: {
    order: ["localStorage", "navigator"],
  },
  saveMissing: true,
  load: "languageOnly",
});

i18n.on("languageChanged", (lng) => {
  localStorage.setItem("i18nextLng", lng);
});

export default i18n;
