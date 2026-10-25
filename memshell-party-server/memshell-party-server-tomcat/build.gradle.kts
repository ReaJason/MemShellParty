plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty Tomcat server support"
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
    // 模板父类（org.apache.catalina.Valve、connector.Request/Response、coyote.UpgradeProtocol…）的生成期桩：
    // 生成引擎按字节解析模板父链时要能在运行时类路径上找到这些类（不会被加载进 JVM，桩接口够用）。
    // 真身 tomcat-embed-core 3.2 MiB，而这里只用到签名 —— 下游（GUI 等）因此不用背一整个内嵌 Tomcat
    implementation(project(":memshell-party-stub:memshell-party-stub-tomcat"))
    // Tests：本模块的 server/injector 与生成引擎（core）配合的验证
    testImplementation(project(":memshell-party-core"))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.tomcat.embed.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
