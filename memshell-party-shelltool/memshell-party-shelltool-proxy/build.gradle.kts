plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Proxy shell tool"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-core"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    // ProxyRawWebSocket: 仅依赖 Servlet 3.1+，不使用 javax.websocket
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    // ProxyWebSocket: javax.websocket.*（WebLogic 通过 ServerContainer 注册端点）
    compileOnly(libs.javax.websocket.api)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.javax.websocket.api)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
