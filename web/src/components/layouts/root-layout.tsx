import { useTranslation } from "react-i18next";
import { NavLink } from "react-router";
import { Outlet } from "react-router-dom";
import { LanguageSwitcher } from "@/components/language-switcher";
import { ModeToggle } from "@/components/mode-toggle.tsx";
import { ThemeProvider } from "@/components/theme-provider.tsx";
import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/sonner";
import { GitHubIcon } from "@/icon";
import { siteConfig } from "@/lib/config";
import { MobileNav } from "../modile-nav";

export default function RootLayout() {
  const { t } = useTranslation("common");
  return (
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <Toaster />
      <div className="flex flex-col h-screen">
        <header className="sticky top-0 z-50 border-b bg-background px-2 sm:px-4 py-2 sm:py-3">
          <div className="flex items-center gap-2">
            <MobileNav className="flex lg:hidden" items={siteConfig.navItems} />
            <div className="hidden lg:flex">
              <NavLink
                to="/"
                className="text-base sm:text-lg font-semibold text-center"
              >
                {siteConfig.name}
              </NavLink>
            </div>
            <nav className="items-center gap-0.5 hidden lg:flex">
              {siteConfig.navItems.map((item) => (
                <Button key={item.href} variant="ghost" size="sm" asChild>
                  <NavLink to={item.href}>{t(item.label)}</NavLink>
                </Button>
              ))}
            </nav>
            <div className="ml-auto flex items-center gap-2 md:flex-1 md:justify-end">
              <LanguageSwitcher />
              <Button
                variant="ghost"
                size="icon"
                className="size-8"
                onClick={() =>
                  window.open("https://github.com/ReaJason/MemShellParty")
                }
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
