plugins {
    id("java-platform")
    id("maven-publish-convention")
}

group = "io.github.reajason"
description =
    "This Bill of Materials POM can be used to ease dependency management when referencing multiple MemShellParty artifacts using Gradle or Maven."
version = rootProject.version

dependencies {
    constraints {
        api("net.bytebuddy:byte-buddy:1.17.5")
        api("org.ow2.asm:asm-commons:9.8")
        api("net.java.dev.jna:jna:5.13.0")
        api("net.java.dev.jna:jna-platform:5.13.0")
        api("javax.servlet:javax.servlet-api:3.0.1")
        api("jakarta.servlet:jakarta.servlet-api:6.0.0")
        api("javax.websocket:javax.websocket-api:1.1")
        api("org.springframework:spring-webmvc:5.3.24")
        api("org.springframework:spring-webflux:5.3.24")
        api("io.projectreactor.netty:reactor-netty-core:1.1.25")
        api("commons-io:commons-io:2.19.0")
        api("org.apache.commons:commons-lang3:3.17.0")
        api("commons-codec:commons-codec:1.18.0")
        api("ch.qos.logback:logback-classic:1.5.18")
        api("org.apache.bcel:bcel:5.2")
        api("org.java-websocket:Java-WebSocket:1.6.0")
        api("com.squareup.okhttp3:okhttp:4.12.0")
        api("com.alibaba.fastjson2:fastjson2:2.0.57")
        api("com.fasterxml.jackson.core:jackson-databind:2.19.0")
        api("org.jetbrains:annotations:26.0.2")
        api("org.mockito:mockito-core:5.18.0")
        api("org.mockito:mockito-junit-jupiter:5.18.0")
        api("org.hamcrest:hamcrest:3.0")
        api("org.junit:junit-bom:5.12.2")
        api("org.testcontainers:testcontainers:1.21.0")
        api("org.testcontainers:junit-jupiter:1.21.0")
    }
}