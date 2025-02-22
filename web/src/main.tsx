import { RouterProvider, createRouter } from "@tanstack/react-router";
import ReactDOM from "react-dom/client";
import { routeTree } from "./routeTree.gen";
import "./index.css";
import { TailwindIndicator } from "@/components/tailwind-indicator.tsx";
import { env } from "@/config.ts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { I18nextProvider } from "react-i18next";
import i18n from "./i18n/i18n";

const queryClient = new QueryClient();

const router = createRouter({
  routeTree,
  basepath: env.BASE_PATH,
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const rootElement = document.getElementById("app") as HTMLElement;

if (!rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>
        <RouterProvider router={router} />
        {env.MODE !== "production" && <TailwindIndicator />}
      </I18nextProvider>
    </QueryClientProvider>,
  );
}
