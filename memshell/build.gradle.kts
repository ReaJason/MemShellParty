plugins {
    id("java")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Normal Java MemShell"
version = rootProject.version


java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation(libs.byte.buddy)
    implementation(libs.asm.commons)
    implementation(libs.javax.servlet.api)
    implementation(libs.javax.websocket.api)
    implementation(libs.spring.webmvc)
    implementation(libs.spring.webflux)
    implementation(libs.reactor.netty.core)
}