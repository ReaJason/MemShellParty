import { RouterProvider, createRouter } from "@tanstack/react-router";
import ReactDOM from "react-dom/client";
import { routeTree } from "./routeTree.gen";
import "./index.css";
import { TailwindIndicator } from "@/components/tailwind-indicator.tsx";
import { Toaster } from "@/components/ui/sonner.tsx";
import { env } from "@/config.ts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient();

const router = createRouter({
  routeTree,
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
      <Toaster />
      <RouterProvider router={router} />
      {env.MODE !== "production" && <TailwindIndicator />}
    </QueryClientProvider>,
  );
}
