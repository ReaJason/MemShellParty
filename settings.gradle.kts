pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
        maven("https://www.jitpack.io")
        maven("https://central.sonatype.com/repository/maven-snapshots")
    }

    includeBuild("build-logic")
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention").version("1.0.0")
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenLocal()
        mavenCentral()
        maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
        maven("https://www.jitpack.io")
        maven("https://central.sonatype.com/repository/maven-snapshots")
    }
}

rootProject.name = "memshell-party"

include("memshell-party-common")

// Compile-time stubs (compileOnly only, never shipped at runtime)
include("memshell-party-stub:memshell-party-stub-jetty")
include("memshell-party-stub:memshell-party-stub-tomcat")

// Core modules
include("memshell-party-api")
include("memshell-party-core")

// Server modules
include("memshell-party-server:memshell-party-server-tomcat")
include("memshell-party-server:memshell-party-server-jetty")
include("memshell-party-server:memshell-party-server-jetty5")
include("memshell-party-server:memshell-party-server-undertow")
include("memshell-party-server:memshell-party-server-jboss")
include("memshell-party-server:memshell-party-server-resin")
include("memshell-party-server:memshell-party-server-resin2")
include("memshell-party-server:memshell-party-server-weblogic")
include("memshell-party-server:memshell-party-server-websphere")
include("memshell-party-server:memshell-party-server-glassfish")
include("memshell-party-server:memshell-party-server-tongweb")
include("memshell-party-server:memshell-party-server-bes")
include("memshell-party-server:memshell-party-server-inforsuite")
include("memshell-party-server:memshell-party-server-apusic")
include("memshell-party-server:memshell-party-server-spring-webmvc")
include("memshell-party-server:memshell-party-server-spring-webflux")
include("memshell-party-server:memshell-party-server-xxljob")
include("memshell-party-server:memshell-party-server-struts2")
include("memshell-party-server:memshell-party-server-dubbo")
include("memshell-party-server:memshell-party-server-all")

// ShellTool modules
include("memshell-party-shelltool:memshell-party-shelltool-godzilla")
include("memshell-party-shelltool:memshell-party-shelltool-behinder")
include("memshell-party-shelltool:memshell-party-shelltool-command")
include("memshell-party-shelltool:memshell-party-shelltool-suo5")
include("memshell-party-shelltool:memshell-party-shelltool-antsword")
include("memshell-party-shelltool:memshell-party-shelltool-neoregeorg")
include("memshell-party-shelltool:memshell-party-shelltool-proxy")
include("memshell-party-shelltool:memshell-party-shelltool-all")

// Examples
include("memshell-party-examples:memshell-party-example-tongweb")
include("memshell-party-examples:memshell-party-example-custom-shelltool")
include("memshell-party-examples:memshell-party-example-custom-shelltool-gui")
include("memshell-party-examples:memshell-party-example-custom-server")
include("memshell-party-examples:memshell-party-example-probe")

include("tools:godzilla", "tools:behinder", "tools:suo5", "tools:ant-sword", "tools:command")
include("memshell-party-packer")
include("memshell-party-boot")
include("integration-test")
include("vul:vul-webapp")
include("vul:vul-webapp-servlet2")
include("vul:vul-webapp-jakarta")
include("vul:vul-webapp-expression")
include("vul:vul-webapp-deserialize")
include("vul:vul-struts2")
include("vul:vul-springboot1")
include("vul:vul-springboot2")
include("vul:vul-springboot2-jetty")
include("vul:vul-springboot2-undertow")
include("vul:vul-springboot3")
include("vul:vul-springboot4")
include("vul:vul-springboot359")
include("vul:vul-springboot2-webflux")
include("vul:vul-springboot3-webflux")
include("vul:vul-springboot4-webflux")
include("vul:vul-playframework")
include("vul:vul-dubbo")
include("memshell-agent:memshell-agent-attacher")
include("memshell-agent:memshell-agent-asm")
include("memshell-agent:memshell-agent-javassist")
include("memshell-agent:memshell-agent-bytebuddy")

// Desktop GUI：SDK（扩展点 + 界面框架，发布给下游当依赖）与完整发行版（SDK + 全量 provider）
include("memshell-party-gui:memshell-party-gui-sdk")
include("memshell-party-gui:memshell-party-gui-app")
// Woodpecker 插件：复用 gui-sdk 的生成链路，把内存马/探测马生成做成 Woodpecker 辅助页签
include("memshell-party-gui:memshell-party-gui-woodpecker")
// Godzilla 插件：复用 gui-sdk 的生成链路，把内存马生成/注入做成 Godzilla 插件页签
include("memshell-party-gui:memshell-party-gui-godzilla-plugin")
// Shiro-550 利用工具：自包含的桌面发行物（探测/爆破/注入流水线），随 Release 发布
include("memshell-party-gui:memshell-party-gui-shiro-exploit")
// FineReport V10 利用工具：自包含的桌面发行物（探测/模板注入/channel 反序列化流水线），随 Release 发布
include("memshell-party-gui:memshell-party-gui-fr-exploit")
