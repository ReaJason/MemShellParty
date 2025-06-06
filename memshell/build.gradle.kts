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
    implementation(platform(project(":memshell-party-bom")))
    implementation("net.bytebuddy:byte-buddy")
    implementation("org.ow2.asm:asm-commons")
    implementation("javax.servlet:javax.servlet-api")
    implementation("javax.websocket:javax.websocket-api")
    implementation("org.springframework:spring-webmvc")
    implementation("org.springframework:spring-webflux")
    implementation("io.projectreactor.netty:reactor-netty-core")
}