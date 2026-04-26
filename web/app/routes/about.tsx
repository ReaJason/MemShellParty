import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import {
  AlertCircle,
  Code,
  Download,
  ExternalLink,
  Globe,
  Heart,
  Mail,
  Package,
  Shield,
  User,
} from "lucide-react";
import { useTheme } from "next-themes";
import { Link } from "react-router";

import { Icons } from "@/components/icons";
import { LineShadowText } from "@/components/magicui/line-shadow-text";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { env } from "@/config";
import { siteConfig } from "@/lib/config";

import { baseOptions } from "../lib/layout.shared";

type VersionInfo = {
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
  releaseUrl: string;
};

export default function AboutPage() {
  const theme = useTheme();
  const shadowColor = theme.theme === "dark" ? "#ffffff" : "#000000";
  const {
    data: updateInfo,
    isPending,
    error,
  } = useQuery<VersionInfo>({
    queryKey: ["version"],
    queryFn: async () => {
      const response = await fetch(`${env.API_URL}/api/version`);
      if (response.ok) {
        return await response.json();
      }
      return "Unknown";
    },
  });
  const inProduction = env.MODE === "production";

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.5,
      },
    },
  };

  return (
    <HomeLayout {...baseOptions()} links={siteConfig.navLinks}>
      <div className="min-h-screen font-sans text-foreground">
        <section className="relative overflow-hidden py-20 text-center">
          <div className="bg-grid-black/[0.05] dark:bg-grid-white/[0.05] absolute top-0 left-0 h-full w-full [mask-image:linear-gradient(to_bottom,white_10%,transparent_100%)]" />
          <div className="relative z-10 container mx-auto px-4">
            <motion.div
              initial={{ opacity: 0, y: -50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              <div className="mb-8 inline-flex items-center rounded-full border border-red-200 bg-red-50 px-4 py-2 text-red-700 transition-colors sm:h-8 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
                <Shield className="mr-2 h-4 w-4" />
                <span className="text-sm">For Security Research & Authorized Testing Only</span>
              </div>
              <h1 className="mb-8 text-5xl font-bold md:text-7xl">
                <span className="text-gray-900 dark:text-white">
                  MemShell
                  <LineShadowText className="italic" shadowColor={shadowColor}>
                    Party
                  </LineShadowText>
                </span>
              </h1>
              <p className="mx-auto mb-12 max-w-4xl text-xl leading-relaxed text-muted-foreground md:text-2xl">
                A self-hosted, visual platform for one-click generation of Java memory shells for
                common middleware and frameworks. The ultimate learning platform for security
                researchers.
              </p>
            </motion.div>
          </div>
        </section>

        {updateInfo?.hasUpdate && inProduction && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="container mx-auto mb-8 px-4"
          >
            <Alert className="w-auto border-green-500 bg-green-50 dark:bg-green-900/20">
              <AlertCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
              <AlertDescription className="flex flex-wrap items-center justify-between gap-4">
                <span className="text-green-800 dark:text-green-300">
                  New version {updateInfo.latestVersion} is available! (Current:{" "}
                  {updateInfo.currentVersion})
                </span>
                <a href={siteConfig.latestRelease} target="_blank" rel="noopener noreferrer">
                  <Button size="sm" className="bg-green-600 text-white hover:bg-green-700">
                    <Download className="mr-2 h-4 w-4" />
                    View Release
                  </Button>
                </a>
              </AlertDescription>
            </Alert>
          </motion.div>
        )}

        <motion.section
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="container mx-auto px-4 py-16"
        >
          <div className="mx-auto grid max-w-6xl gap-8 md:grid-cols-2">
            <motion.div variants={itemVariants}>
              <Card className="h-full">
                <CardContent className="p-6">
                  <div className="mb-4 flex items-center">
                    <Package className="mr-3 h-6 w-6 text-primary" />
                    <h2 className="text-2xl font-bold">Version</h2>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between border-b border-border/50 py-2">
                      <span className="text-muted-foreground">Current Version</span>
                      <Badge variant="secondary">{updateInfo?.currentVersion || "v0.0.0"}</Badge>
                    </div>
                    <div className="flex items-center justify-between border-b border-border/50 py-2">
                      <span className="text-muted-foreground">Latest Version</span>
                      {isPending && <span className="text-sm text-gray-500">Checking...</span>}
                      {error && <Badge variant="destructive">{error.message}</Badge>}
                      {updateInfo && !error && (
                        <Badge variant="outline">{updateInfo.latestVersion}</Badge>
                      )}
                    </div>
                    <div className="flex items-center justify-between border-b border-border/50 py-2">
                      <span className="text-muted-foreground">License</span>
                      <Badge variant="outline">MIT License</Badge>
                    </div>
                  </div>
                </CardContent>
                <CardFooter className="flex justify-between">
                  <span className="text-xs text-gray-500">
                    Last test time: {new Date().toLocaleString()}
                  </span>
                </CardFooter>
              </Card>
            </motion.div>

            <motion.div variants={itemVariants}>
              <Card className="h-full">
                <CardContent className="p-6">
                  <div className="mb-4 flex items-center">
                    <User className="mr-3 h-6 w-6 text-primary" />
                    <h2 className="text-2xl font-bold">Author</h2>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <Avatar className="h-16 w-16">
                        <AvatarImage src="https://cdn.jsdelivr.net/gh/ReaJason/blog_imgs/default/blog_avatar.jpg" />
                        <AvatarFallback>RJ</AvatarFallback>
                      </Avatar>
                      <div>
                        <h3 className="text-lg font-semibold">{siteConfig.author}</h3>
                        <p className="text-sm text-muted-foreground">{siteConfig.authorIntro}</p>
                      </div>
                    </div>
                    <div className="space-y-2 pt-2">
                      <a
                        href={siteConfig.blog}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-muted-foreground transition-colors hover:text-primary"
                      >
                        <Globe className="h-4 w-4" />
                        <span className="text-sm">reajason.eu.org</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                      <a
                        href={siteConfig.authorGithub}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-muted-foreground transition-colors hover:text-primary"
                      >
                        <Icons.gitHub className="h-4 w-4" />
                        <span className="text-sm">github.com/ReaJason</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <Mail className="h-4 w-4" />
                        <span className="text-sm">Contact via GitHub</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </motion.section>

        <motion.section
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="container mx-auto px-4 py-16"
        >
          <div className="mx-auto max-w-6xl">
            <div className="mb-12 text-center">
              <h2 className="mb-4 text-3xl font-bold">Resources & Links</h2>
              <p className="text-muted-foreground">
                Explore documentation and contribute to the project
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-3">
              <Card className="group transition-shadow hover:shadow-lg">
                <CardContent className="p-6">
                  <Code className="mb-4 h-10 w-10 text-primary transition-transform group-hover:scale-110" />
                  <h3 className="mb-2 text-lg font-semibold">Documentation</h3>
                  <p className="mb-4 text-sm text-muted-foreground">
                    Comprehensive guides and API references for using MemShellParty effectively.
                  </p>
                  <Link
                    className="flex items-center gap-1 text-sm font-medium text-primary hover:underline"
                    to="/docs"
                  >
                    Read Docs <ExternalLink className="h-3 w-3" />
                  </Link>
                </CardContent>
              </Card>

              <Card className="group transition-shadow hover:shadow-lg">
                <CardContent className="p-6">
                  <Icons.gitHub className="mb-4 h-10 w-10 text-primary transition-transform group-hover:scale-110" />
                  <h3 className="mb-2 text-lg font-semibold">Source Code</h3>
                  <p className="mb-4 text-sm text-muted-foreground">
                    View the source code, report issues, and contribute to the development.
                  </p>
                  <a
                    href={siteConfig.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-sm font-medium text-primary hover:underline"
                  >
                    View Repository <ExternalLink className="h-3 w-3" />
                  </a>
                </CardContent>
              </Card>

              <Card className="group transition-shadow hover:shadow-lg">
                <CardContent className="p-6">
                  <Heart className="mb-4 h-10 w-10 text-primary transition-transform group-hover:scale-110" />
                  <h3 className="mb-2 text-lg font-semibold">Support</h3>
                  <p className="mb-4 text-sm text-muted-foreground">
                    Star the project on GitHub and share it with the security community.
                  </p>
                  <a
                    href={siteConfig.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-sm font-medium text-primary hover:underline"
                  >
                    Star on GitHub <ExternalLink className="h-3 w-3" />
                  </a>
                </CardContent>
              </Card>
            </div>
          </div>
        </motion.section>

        <footer className="mt-16 border-t py-8">
          <div className="container mx-auto flex flex-col gap-4 px-4 text-center sm:flex-row sm:items-center sm:justify-between sm:text-left">
            <div>
              <p className="text-sm font-semibold">{siteConfig.name}</p>
              <p className="text-xs text-muted-foreground">
                Built with ❤️ by{" "}
                <a
                  href={siteConfig.blog}
                  rel="noreferrer noopener"
                  target="_blank"
                  className="font-medium transition-colors hover:text-primary"
                >
                  {siteConfig.author}
                </a>
              </p>
            </div>
            <div className="text-xs text-muted-foreground">
              © 2025 {siteConfig.name}. For authorized security testing only.
            </div>
          </div>
        </footer>
      </div>
    </HomeLayout>
  );
}
