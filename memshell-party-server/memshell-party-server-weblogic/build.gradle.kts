plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty WebLogic server support"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-api"))
    annotationProcessor(libs.metainf.services)
    compileOnly(libs.metainf.services)
    api(project(":memshell-party-server:memshell-party-server-tomcat"))
    implementation(libs.javax.servlet.api)
    // WebSocket 模板实现 JSR-356 javax.websocket.*，生成引擎按字节解析模板接口时需要这些
    // 签名在运行时类路径上（不会被加载；真身由 WebLogic 自带）
    implementation(libs.javax.websocket.api)
}
