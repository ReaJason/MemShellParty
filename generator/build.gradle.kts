plugins {
    id("java")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

group = "io.github.reajason"
description = "MemShell Generator for Java"
version = rootProject.version

tasks.compileTestJava {
    javaCompiler.set(javaToolchains.compilerFor {
        languageVersion.set(JavaLanguageVersion.of(17))
    })
}

tasks.test {
    useJUnitPlatform()
}

dependencies {
    implementation(project(":memshell-party-common"))
    implementation(project(":packer"))
    implementation(libs.byte.buddy)
    implementation(libs.asm.commons)
    implementation(libs.javax.websocket.api)
    implementation(libs.javax.servlet.api)
    implementation(libs.spring.webmvc)
    implementation(libs.spring.webflux)
    implementation(libs.reactor.netty.core)
    implementation(libs.jackson.annotations)
    implementation(libs.bundles.jna)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.hamcrest)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.bundles.mockito)
}