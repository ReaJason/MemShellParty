plugins {
    id("java-library")
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Aggregate module that includes all built-in shell tool providers"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-behinder"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-command"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-suo5"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-antsword"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-neoregeorg"))
    api(project(":memshell-party-shelltool:memshell-party-shelltool-proxy"))
}
