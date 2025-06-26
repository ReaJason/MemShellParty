import { createHashRouter } from "react-router-dom";
import RootLayout from "@/components/layouts/root-layout";
import { env } from "@/config";
import MemShellPage from "@/pages/memshell";
import { FormSchema } from "@/types/schema";
import DetectionPage from "./pages/detection";
import MemShellPartyLandingPage from "./pages/landing";

// Function to parse URL parameters into form default values
const parseUrlParams = (searchParams: URLSearchParams): Partial<FormSchema> => {
  const result: Partial<FormSchema> = {};

  // Helper function to parse boolean values
  const parseBoolean = (value: string | null): boolean | undefined => {
    if (value === null) return undefined;
    return value.toLowerCase() === "true";
  };

  // Map URL parameters to form fields
  if (searchParams.has("server")) result.server = searchParams.get("server") ?? undefined;
  if (searchParams.has("targetJdkVersion")) result.targetJdkVersion = searchParams.get("targetJdkVersion") ?? undefined;
  if (searchParams.has("debug")) result.debug = parseBoolean(searchParams.get("debug"));
  if (searchParams.has("bypassJavaModule"))
    result.bypassJavaModule = parseBoolean(searchParams.get("bypassJavaModule"));
  if (searchParams.has("shellClassName")) result.shellClassName = searchParams.get("shellClassName") ?? undefined;
  if (searchParams.has("shellTool")) result.shellTool = searchParams.get("shellTool") ?? undefined;
  if (searchParams.has("shellType")) result.shellType = searchParams.get("shellType") ?? undefined;
  if (searchParams.has("urlPattern")) result.urlPattern = searchParams.get("urlPattern") ?? undefined;
  if (searchParams.has("godzillaPass")) result.godzillaPass = searchParams.get("godzillaPass") ?? undefined;
  if (searchParams.has("godzillaKey")) result.godzillaKey = searchParams.get("godzillaKey") ?? undefined;
  if (searchParams.has("behinderPass")) result.behinderPass = searchParams.get("behinderPass") ?? undefined;
  if (searchParams.has("antSwordPass")) result.antSwordPass = searchParams.get("antSwordPass") ?? undefined;
  if (searchParams.has("commandParamName")) result.commandParamName = searchParams.get("commandParamName") ?? undefined;
  if (searchParams.has("headerName")) result.headerName = searchParams.get("headerName") ?? undefined;
  if (searchParams.has("headerValue")) result.headerValue = searchParams.get("headerValue") ?? undefined;
  if (searchParams.has("injectorClassName"))
    result.injectorClassName = searchParams.get("injectorClassName") ?? undefined;
  if (searchParams.has("packingMethod")) result.packingMethod = searchParams.get("packingMethod") ?? undefined;
  if (searchParams.has("shrink")) result.shrink = parseBoolean(searchParams.get("shrink"));
  if (searchParams.has("shellClassBase64")) result.shellClassBase64 = searchParams.get("shellClassBase64") ?? undefined;

  return result;
};

export const router = createHashRouter(
  [
    {
      path: "/",
      element: <RootLayout />,
      children: [
        {
          index: true,
          element: <MemShellPartyLandingPage />,
        },
        {
          path: "memshell",
          element: <MemShellPage />,
          loader: ({ request }) => {
            const url = new URL(request.url);
            return parseUrlParams(url.searchParams);
          },
        },
        {
          path: "detection",
          element: <DetectionPage />,
        },
      ],
    },
  ],
  {
    basename: env.BASE_PATH,
  },
);
