import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import type {ReactNode} from "react";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
});

export function QueryProvider({ children }: Readonly<{ children: ReactNode }>) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
