pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }

    includeBuild("build-logic")
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention").version("1.0.0")
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
    }
}

rootProject.name = "memshell-party"

include("memshell-party-common")
include("tools:godzilla", "tools:behinder", "tools:suo5", "tools:ant-sword")
include("packer")
include("boot")
include("generator")
include("integration-test")
include("vul:vul-webapp")
include("vul:vul-webapp-jakarta")
include("vul:vul-webapp-expression")
include("vul:vul-webapp-deserialize")
include("vul:vul-springboot1")
include("vul:vul-springboot2")
include("vul:vul-springboot2-jetty")
include("vul:vul-springboot2-undertow")
include("vul:vul-springboot3")
include("vul:vul-springboot2-webflux")
include("vul:vul-springboot3-webflux")
include("memshell-agent:memshell-agent-attacher")
include("memshell-agent:memshell-agent-asm")
include("memshell-agent:memshell-agent-javassist")
include("memshell-agent:memshell-agent-bytebuddy")