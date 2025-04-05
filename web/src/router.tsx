import { createBrowserRouter } from "react-router-dom";
import { env } from "@/config";
import RootLayout from "@/components/layouts/root-layout";
import IndexPage from "@/pages";

export const router = createBrowserRouter(
  [
    {
      path: "/",
      element: <RootLayout />,
      children: [
        {
          index: true,
          element: <IndexPage />,
        },
      ],
    },
  ],
  {
    basename: env.BASE_PATH,
  }
); 