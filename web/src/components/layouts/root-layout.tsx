import { LanguageSwitcher } from "@/components/language-switcher";
import { ModeToggle } from "@/components/mode-toggle.tsx";
import { ThemeProvider } from "@/components/theme-provider.tsx";
import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/sonner";
import VersionBadge from "@/components/version-badge";
import { GitHubIcon } from "@/icon";
import { Outlet } from "react-router-dom";

export default function RootLayout() {
  return (
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <Toaster />
      <div className="flex flex-col h-screen">
        <header className="sticky top-0 z-50 border-b bg-background px-2 sm:px-4 py-2 sm:py-3">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 sm:gap-0">
            <div className="flex items-center">
              <h2 className="text-base sm:text-lg font-semibold text-center">MemShellParty - JavaWeb</h2>
            </div>
            <div className="flex items-center gap-0.5 sm:gap-1">
              <VersionBadge />
              <LanguageSwitcher />
              <Button
                variant="ghost"
                size="icon"
                className="size-8"
                onClick={() => window.open("https://github.com/ReaJason/MemShellParty")}
              >
                <GitHubIcon />
              </Button>
              <ModeToggle />
            </div>
          </div>
        </header>
        <main className="flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </ThemeProvider>
  );
}
