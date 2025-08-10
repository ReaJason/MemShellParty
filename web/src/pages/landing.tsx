import {motion} from "framer-motion";
import {
    CombineIcon,
    GithubIcon,
    MinimizeIcon,
    ServerIcon,
    ShellIcon,
    Shield,
    ShieldCheckIcon,
    TerminalIcon,
    ZapIcon,
} from "lucide-react";
import {NavLink} from "react-router-dom";
import {LineShadowText} from "@/components/magicui/line-shadow-text";
import {RainbowButton} from "@/components/magicui/rainbow-button";
import {useTheme} from "@/components/theme-provider";
import {Badge} from "@/components/ui/badge";
import {Button} from "@/components/ui/button";
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from "@/components/ui/card";

export default function LandingPage() {
  const features = [
    {
      icon: <ShieldCheckIcon className="w-8 h-8 text-green-400" />,
      title: "Non-Intrusive",
      description:
        "Generated memshells don't interfere with normal middleware traffic, even with multiple shells injected.",
    },
    {
      icon: <ZapIcon className="w-8 h-8 text-yellow-400" />,
      title: "High Availability",
      description: "Comes with comprehensive CI integration tests, covering mainstream middleware for reliability.",
    },
    {
      icon: <MinimizeIcon className="w-8 h-8 text-blue-400" />,
      title: "Minimal Size",
      description: "The core code of the memshell is kept as concise as possible for efficient transfer and injection.",
    },
    {
      icon: <CombineIcon className="w-8 h-8 text-purple-400" />,
      title: "Strong Compatibility",
      description: "Covers common middleware and frameworks like Tomcat, WebLogic, and Spring.",
    },
  ];

  const supportedMiddleware = [
    "Tomcat",
    "Jetty",
    "GlassFish",
    "Payara",
    "Resin",
    "SpringWebMVC",
    "SpringWebFlux",
    "XXL-JOB",
    "JBossAS",
    "JBossEAP",
    "WildFly",
    "Undertow",
    "WebLogic",
    "WebSphere",
    "BES",
    "TongWeb",
    "InforSuite AS",
    "Apusic AS",
    "Primeton",
  ];
  const supportedShells = [
    "Godzilla",
    "Behinder",
    "AntSword",
    "Suo5",
    "Neo-reGeorg",
    "Command Execution",
    "Custom Shell",
  ];

  const theme = useTheme();
  const shadowColor = theme.theme === "dark" ? "#ffffff" : "#000000";

  return (
    <div className="min-h-screen font-sans bg-background text-foreground">
      <section className="relative text-center py-20 overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-full bg-grid-black/[0.05] dark:bg-grid-white/[0.05] [mask-image:linear-gradient(to_bottom,white_10%,transparent_100%)]" />
        <div className="container mx-auto px-4 relative z-10">
          <motion.div initial={{ opacity: 0, y: -50 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }}>
            <div className="inline-flex items-center px-4 py-2 rounded-full border sm:h-8 mb-8 transition-colors dark:bg-red-900/20 dark:border-red-800 dark:text-red-300 bg-red-50 border-red-200 text-red-700">
              <Shield className="w-4 h-4 mr-2" />
              <span className="text-sm">For Security Research & Authorized Testing Only</span>
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
              A self-hosted, visual platform for one-click generation of Java memory shells for common middleware and
              frameworks. The ultimate learning platform for security researchers.
            </p>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="mt-8 flex justify-center gap-4 flex-wrap"
          >
            <NavLink to="/memshell">
              <Button size="lg">
                <TerminalIcon className="mr-2 h-5 w-5" />
                Get Started
              </Button>
            </NavLink>
            <a href="https://github.com/ReaJason/MemShellParty" target="_blank" rel="noopener noreferrer">
              <Button size="lg" variant="outline">
                <GithubIcon className="mr-2 h-5 w-5" />
                View on GitHub
              </Button>
            </a>
          </motion.div>
        </div>
      </section>

      <section className="py-20 bg-secondary/30">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Why Choose MemShellParty?</h2>
            <p className="mt-3 text-lg text-muted-foreground">Designed for modern offensive and defensive scenarios.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.5 }}
                transition={{ delay: index * 0.1 }}
              >
                <Card className="h-full border-border/60 bg-card">
                  <CardHeader className="flex flex-row items-center gap-4">
                    {feature.icon}
                    <CardTitle className="text-lg">{feature.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription>{feature.description}</CardDescription>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Extensive Support Matrix</h2>
            <p className="mt-3 text-lg text-muted-foreground">
              Compatible with a wide range of industry-standard technologies.
            </p>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ duration: 0.5 }}
            >
              <Card className="h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ServerIcon className="w-6 h-6" />
                    Supported Middleware
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-wrap gap-2  mt-2">
                  {supportedMiddleware.map((tech) => (
                    <Badge key={tech} variant="secondary" className="text-base py-1 px-3">
                      {tech}
                    </Badge>
                  ))}
                </CardContent>
              </Card>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ duration: 0.5 }}
            >
              <Card className="h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ShellIcon className="w-6 h-6" />
                    Supported Shell Tools
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-wrap gap-2 mt-2">
                  {supportedShells.map((shell) => (
                    <Badge key={shell} variant="secondary" className="text-base py-1 px-3">
                      {shell}
                    </Badge>
                  ))}
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </div>
      </section>

      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Get Your Shell in 3 Simple Steps</h2>
            <p className="mt-3 text-lg text-muted-foreground">A streamlined process from selection to generation.</p>
          </div>
          <div className="max-w-4xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ delay: 0.1 }}
              className="flex flex-col items-center"
            >
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-primary text-primary-foreground text-2xl font-bold mb-4">
                1
              </div>
              <h3 className="text-xl font-semibold mb-2">Select Middleware</h3>
              <p className="text-muted-foreground">Choose your target environment like Tomcat or Spring.</p>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ delay: 0.2 }}
              className="flex flex-col items-center"
            >
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-primary text-primary-foreground text-2xl font-bold mb-4">
                2
              </div>
              <h3 className="text-xl font-semibold mb-2">Configure Shell</h3>
              <p className="text-muted-foreground">Pick a shell type and set parameters like passwords or keys.</p>
            </motion.div>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.5 }}
              transition={{ delay: 0.3 }}
              className="flex flex-col items-center"
            >
              <div className="flex items-center justify-center w-16 h-16 rounded-full bg-primary text-primary-foreground text-2xl font-bold mb-4">
                3
              </div>
              <h3 className="text-xl font-semibold mb-2">Generate Payload</h3>
              <p className="text-muted-foreground">Click generate to get the final payload for your operation.</p>
            </motion.div>
          </div>
        </div>
      </section>

      {/* --- Final CTA Section --- */}
      <section className="py-20 text-center bg-secondary/30">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Ready to Join the Party?</h2>
          <p className="mt-4 text-lg text-muted-foreground max-w-xl mx-auto">
            Visit the GitHub repository to start your memshell exploration, or contribute to the project!
          </p>
          <div className="mt-8">
            <a href="https://github.com/ReaJason/MemShellParty" target="_blank" rel="noopener noreferrer">
              <RainbowButton size="lg">
                <GithubIcon className="mr-2 h-5 w-5" />
                Star & Fork on GitHub
              </RainbowButton>
            </a>
          </div>
        </div>
      </section>

      {/* --- Footer --- */}
      <footer className="border-t py-8">
        <div className="container mx-auto px-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between text-center sm:text-left">
          <div>
            <p className="text-sm font-semibold">MemShellParty</p>
            <p className="text-xs">
              Built with ❤️ by{" "}
              <a href="https://reajason.eu.org" rel="noreferrer noopener" target="_blank" className="font-medium">
                ReaJason
              </a>
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
