import ReactDOM from "react-dom/client";
import "./index.css";
import { I18nextProvider } from "react-i18next";
import { RouterProvider } from "react-router-dom";
import { TailwindIndicator } from "@/components/tailwind-indicator.tsx";
import { env } from "@/config.ts";
import i18n from "./i18n/i18n";
import { QueryProvider } from "./providers/query-client-provider";
import { router } from "./router";

const rootElement = document.getElementById("app") as HTMLElement;

if (!rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <QueryProvider>
      <I18nextProvider i18n={i18n}>
        <RouterProvider router={router} />
        {env.MODE !== "production" && <TailwindIndicator />}
      </I18nextProvider>
    </QueryProvider>,
  );
}
