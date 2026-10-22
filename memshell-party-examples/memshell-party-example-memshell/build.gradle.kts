plugins {
    id("java")
}

group = "io.github.reajason"
description = "Example: generate memory shells with MemShellGenerator (Godzilla and Agent)"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // 生成引擎 + 查询门面（MemShellGenerator / ShellTypeCatalog / ToolConfigFactory）
    implementation(project(":memshell-party-core"))
    // 投递编码（Base64 / gzip / AgentJar / 带 Attacher 的 AgentJar）
    implementation(project(":memshell-party-packer"))
    // server 插件：Tomcat 的注入器模板（Filter/Servlet/Valve/WebSocket 以及 Agent 类型）
    implementation(project(":memshell-party-server:memshell-party-server-tomcat"))
    // shelltool 插件：Godzilla 的 shell 模板与配置
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))

    // 测试会把生成的 Filter 类真正 load 进 JVM 断言字段，需要它的父接口 javax.servlet.Filter
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
