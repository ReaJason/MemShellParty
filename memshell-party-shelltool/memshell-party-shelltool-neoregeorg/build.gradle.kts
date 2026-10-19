plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty NeoreGeorg shell tool"
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
    // NeoreGeorgValve: org.apache.catalina.*（编译期桩）
    compileOnly(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // NeoreGeorgInterceptor/ControllerHandler: org.springframework.web.servlet.*
    compileOnly(libs.spring.webmvc)
    // Servlet/Filter/Listener 模板: javax.servlet.*
    compileOnly(libs.javax.servlet.api)
    testImplementation(libs.junit.jupiter)
    // 生成期解析模板父类签名（javax.servlet.Filter 等），与 godzilla 模块同一处理
    testImplementation(libs.javax.servlet.api)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
