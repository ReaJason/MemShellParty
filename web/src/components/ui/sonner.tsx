import { Toaster as Sonner } from "sonner";
import { useTheme } from "@/components/theme-provider.tsx";

type ToasterProps = React.ComponentProps<typeof Sonner>;

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme } = useTheme();
  return (
    <Sonner theme={theme as ToasterProps["theme"]} richColors className="toaster group" toastOptions={{}} {...props} />
  );
};

export { Toaster };
