import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { HomeLayout } from "fumadocs-ui/layouts/home";
import {
  AlertCircle,
  Code,
  Download,
  ExternalLink,
  Github,
  Globe,
  Heart,
  Mail,
  Package,
  Shield,
  User,
} from "lucide-react";
import { useTheme } from "next-themes";
import { Link } from "react-router";
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
        <section className="relative text-center py-20 overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-full bg-grid-black/[0.05] dark:bg-grid-white/[0.05] [mask-image:linear-gradient(to_bottom,white_10%,transparent_100%)]" />
          <div className="container mx-auto px-4 relative z-10">
            <motion.div
              initial={{ opacity: 0, y: -50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              <div className="inline-flex items-center px-4 py-2 rounded-full border sm:h-8 mb-8 transition-colors dark:bg-red-900/20 dark:border-red-800 dark:text-red-300 bg-red-50 border-red-200 text-red-700">
                <Shield className="w-4 h-4 mr-2" />
                <span className="text-sm">
                  For Security Research & Authorized Testing Only
                </span>
              </div>
              <h1 className="text-5xl md:text-7xl font-bold mb-8">
                <span className="dark:text-white text-gray-900">
                  MemShell
                  <LineShadowText className="italic" shadowColor={shadowColor}>
                    Party
                  </LineShadowText>
                </span>
              </h1>
              <p className="text-xl md:text-2xl mb-12 max-w-4xl mx-auto leading-relaxed text-muted-foreground">
                A self-hosted, visual platform for one-click generation of Java
                memory shells for common middleware and frameworks. The ultimate
                learning platform for security researchers.
              </p>
            </motion.div>
          </div>
        </section>

        {updateInfo?.hasUpdate && inProduction && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="container mx-auto px-4 mb-8"
          >
            <Alert className="border-green-500 bg-green-50 dark:bg-green-900/20 w-auto">
              <AlertCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
              <AlertDescription className="flex items-center justify-between flex-wrap gap-4">
                <span className="text-green-800 dark:text-green-300">
                  New version {updateInfo.latestVersion} is available! (Current:{" "}
                  {updateInfo.currentVersion})
                </span>
                <a
                  href={siteConfig.latestRelease}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button
                    size="sm"
                    className="bg-green-600 hover:bg-green-700 text-white"
                  >
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
          <div className="grid md:grid-cols-2 gap-8 max-w-6xl mx-auto">
            <motion.div variants={itemVariants}>
              <Card className="h-full">
                <CardContent className="p-6">
                  <div className="flex items-center mb-4">
                    <Package className="w-6 h-6 mr-3 text-primary" />
                    <h2 className="text-2xl font-bold">Version</h2>
                  </div>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center py-2 border-b border-border/50">
                      <span className="text-muted-foreground">
                        Current Version
                      </span>
                      <Badge variant="secondary">
                        {updateInfo?.currentVersion || "v0.0.0"}
                      </Badge>
                    </div>
                    <div className="flex justify-between items-center py-2 border-b border-border/50">
                      <span className="text-muted-foreground">
                        Latest Version
                      </span>
                      {isPending && (
                        <span className="text-sm text-gray-500">
                          Checking...
                        </span>
                      )}
                      {error && (
                        <Badge variant="destructive">{error.message}</Badge>
                      )}
                      {updateInfo && !error && (
                        <Badge variant="outline">
                          {updateInfo.latestVersion}
                        </Badge>
                      )}
                    </div>
                    <div className="flex justify-between items-center py-2 border-b border-border/50">
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
                  <div className="flex items-center mb-4">
                    <User className="w-6 h-6 mr-3 text-primary" />
                    <h2 className="text-2xl font-bold">Author</h2>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <Avatar className="w-16 h-16">
                        <AvatarImage src="https://cdn.jsdelivr.net/gh/ReaJason/blog_imgs/default/blog_avatar.jpg" />
                        <AvatarFallback>RJ</AvatarFallback>
                      </Avatar>
                      <div>
                        <h3 className="font-semibold text-lg">
                          {siteConfig.author}
                        </h3>
                        <p className="text-sm text-muted-foreground">
                          {siteConfig.authorIntro}
                        </p>
                      </div>
                    </div>
                    <div className="space-y-2 pt-2">
                      <a
                        href={siteConfig.blog}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors"
                      >
                        <Globe className="w-4 h-4" />
                        <span className="text-sm">reajason.eu.org</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                      <a
                        href={siteConfig.authorGithub}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-muted-foreground hover:text-primary transition-colors"
                      >
                        <Github className="w-4 h-4" />
                        <span className="text-sm">github.com/ReaJason</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <Mail className="w-4 h-4" />
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
          <div className="max-w-6xl mx-auto">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold mb-4">Resources & Links</h2>
              <p className="text-muted-foreground">
                Explore documentation and contribute to the project
              </p>
            </div>
            <div className="grid md:grid-cols-3 gap-6">
              <Card className="group hover:shadow-lg transition-shadow">
                <CardContent className="p-6">
                  <Code className="w-10 h-10 mb-4 text-primary group-hover:scale-110 transition-transform" />
                  <h3 className="font-semibold text-lg mb-2">Documentation</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Comprehensive guides and API references for using
                    MemShellParty effectively.
                  </p>
                  <Link
                    className="text-primary hover:underline text-sm font-medium flex items-center gap-1"
                    to="/docs"
                  >
                    Read Docs <ExternalLink className="w-3 h-3" />
                  </Link>
                </CardContent>
              </Card>

              <Card className="group hover:shadow-lg transition-shadow">
                <CardContent className="p-6">
                  <Github className="w-10 h-10 mb-4 text-primary group-hover:scale-110 transition-transform" />
                  <h3 className="font-semibold text-lg mb-2">Source Code</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    View the source code, report issues, and contribute to the
                    development.
                  </p>
                  <a
                    href={siteConfig.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline text-sm font-medium flex items-center gap-1"
                  >
                    View Repository <ExternalLink className="w-3 h-3" />
                  </a>
                </CardContent>
              </Card>

              <Card className="group hover:shadow-lg transition-shadow">
                <CardContent className="p-6">
                  <Heart className="w-10 h-10 mb-4 text-primary group-hover:scale-110 transition-transform" />
                  <h3 className="font-semibold text-lg mb-2">Support</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Star the project on GitHub and share it with the security
                    community.
                  </p>
                  <a
                    href={siteConfig.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline text-sm font-medium flex items-center gap-1"
                  >
                    Star on GitHub <ExternalLink className="w-3 h-3" />
                  </a>
                </CardContent>
              </Card>
            </div>
          </div>
        </motion.section>

        <footer className="border-t py-8 mt-16">
          <div className="container mx-auto px-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between text-center sm:text-left">
            <div>
              <p className="text-sm font-semibold">{siteConfig.name}</p>
              <p className="text-xs text-muted-foreground">
                Built with ❤️ by{" "}
                <a
                  href={siteConfig.blog}
                  rel="noreferrer noopener"
                  target="_blank"
                  className="font-medium hover:text-primary transition-colors"
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
