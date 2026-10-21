import type { ReactNode } from "react";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      // 后端冷启动/网关抖动时多试几次（1s、2s、4s 退避），仍然失败再由页面展示错误和重试入口
      retry: 3,
    },
  },
});

export function QueryProvider({ children }: Readonly<{ children: ReactNode }>) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
