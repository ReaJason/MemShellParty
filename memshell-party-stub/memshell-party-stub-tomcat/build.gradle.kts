plugins {
    id("java-library")
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Tomcat compile-time stubs for MemShellParty shell templates (Valve/Request/Response, coyote upgrade protocol)"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // Request/Response 实现 HttpServletRequest(ServletResponse)，InternalHttpUpgradeHandler 继承
    // HttpUpgradeHandler —— 模板编译时按字节解析这些父类型，运行时由使用方的 servlet-api 提供
    compileOnly(libs.javax.servlet.api)
}
