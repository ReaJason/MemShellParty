plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Dubbo server support"
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
    // 注入器模板引用的 Dubbo 2.6/2.7 类型签名桩：生成引擎按字节解析模板时需要它在运行时
    // 类路径上（不会被加载进 JVM）。真身两个 jar 共 4.6 MiB，这里只保留注入器用到的签名，
    // 下游（GUI/插件）因此不用背 Spring/Netty/Gson 等整条 Dubbo 传递链。
    implementation(project(":memshell-party-stub:memshell-party-stub-dubbo"))
    // 注入器源码直接以 javassist.ClassPool 作为 ClassGenerator.getClassPool 的接收类型；
    // 目标环境的 Dubbo 自带 javassist，生成期不需要它
    compileOnly(libs.javassist)
}
