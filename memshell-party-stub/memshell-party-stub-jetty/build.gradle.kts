plugins {
    id("java-library")
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Jetty compile-time stubs for MemShellParty shell templates (compileOnly only, never ship at runtime)"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    compileOnly(libs.javax.servlet.api)
}
