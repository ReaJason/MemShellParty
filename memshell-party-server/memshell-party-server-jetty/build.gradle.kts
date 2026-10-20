plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Jetty server support"
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
    implementation(libs.javax.servlet.api)
    // Jetty 模板父类（org.eclipse.jetty.server.Handler 等）的编译期桩：生成期按字节解析
    // 模板父链时需要它在运行时类路径上（不会加载进 JVM），随本模块一起走
    implementation(project(":memshell-party-stub:memshell-party-stub-jetty"))
}
