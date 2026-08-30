import { ExternalLinkIcon } from "lucide-react";
import type { LinkItemType } from "fumadocs-ui/layouts/shared";

import { useTranslation } from "react-i18next";

import { LanguageSwitcher } from "@/components/language-switcher";
import { env } from "@/config";

type NavLabelKey = "MemShellGenerator" | "ProbeShellGenerator" | "documents" | "about";

function NavLabel({ translationKey }: { translationKey: NavLabelKey }) {
  const { t } = useTranslation("common");

  return t(translationKey);
}

const basePath = env.BASE_PATH?.replace(/^\/+|\/+$/g, "") ?? "";
const docsUrl = `/${basePath ? `${basePath}/` : ""}docs`;

export const siteConfig = {
  name: "MemShellParty",
  url: "https://party.memshell.news",
  github: "https://github.com/ReaJason/MemShellParty",
  latestRelease: "https://github.com/ReaJason/MemShellParty/releases/latest",
  author: "ReaJason",
  authorGithub: "https://github.com/ReaJason",
  authorIntro: "Java RASP Developer",
  blog: "https://reajason.eu.org",
  navLinks: [
    {
      text: <NavLabel translationKey="MemShellGenerator" />,
      url: "/memshell",
    },
    {
      text: <NavLabel translationKey="ProbeShellGenerator" />,
      url: "/probeshell",
    },
    {
      text: (
        <span className="inline-flex items-center gap-1.5">
          <NavLabel translationKey="documents" />
          <ExternalLinkIcon aria-hidden="true" className="size-3.5" />
        </span>
      ),
      url: docsUrl,
      external: true,
    },
    {
      text: <NavLabel translationKey="about" />,
      url: "/about",
    },
    {
      type: "custom",
      children: <LanguageSwitcher />,
      secondary: true,
    },
  ] as LinkItemType[],
};
