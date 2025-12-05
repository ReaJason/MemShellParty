import type { LinkItemType } from "fumadocs-ui/layouts/shared";
import { LanguageSwitcher } from "@/components/language-switcher";

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
      text: "MemShellGenerator",
      url: "/memshell",
    },
    {
      text: "ProbeShellGenerator",
      url: "/probeshell",
    },
    {
      text: "Documents",
      url: "/docs",
    },
    {
      text: "About",
      url: "/about",
    },
    {
      type: "custom",
      children: <LanguageSwitcher />,
      secondary: true,
    },
  ] as LinkItemType[],
};
