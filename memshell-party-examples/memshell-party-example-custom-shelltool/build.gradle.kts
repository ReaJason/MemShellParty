plugins {
    id("java-library")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
description = "Example: implement your own MemShellParty ShellTool plugin (SPI)"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // 生成引擎：ShellToolProvider / ShellToolConfig / ByteBuddyShellGenerator / ToolMapping 都在这里
    api(project(":memshell-party-core"))

    // 生成期依赖：模板的父接口 javax.servlet.* 要能以字节方式解析（不会被加载进 JVM）。
    // 与内置 shelltool 模块一样用 compileOnly —— 使用方按自己打的目标类型补依赖。
    compileOnly(libs.javax.servlet.api)
    // SPI 注册文件由注解处理器生成（@MetaInfServices）
    compileOnly(libs.metainf.services)
    annotationProcessor(libs.metainf.services)

    // 目标 server：示例以 Tomcat 生成 / 验证 Filter、Servlet、Listener。
    // 排除 Tomcat 桩：本模块端到端测试会内嵌真 Tomcat，桩与 tomcat-embed-core 同包名，
    // 留在类路径上会遮蔽真身（boot 上表现为 NoSuchMethodError: Adapter.getDomain()）
    testImplementation(project(":memshell-party-server:memshell-party-server-tomcat")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }
    // 同一个插件在别的 servlet 容器上同样可用（这里只做生成期验证）
    testImplementation(project(":memshell-party-server:memshell-party-server-undertow"))
    // 端到端测试：内嵌 Tomcat 跑内存马 + 仓库内的哥斯拉协议客户端（tools:godzilla）
    testImplementation(libs.tomcat.embed.core)
    testImplementation(libs.javax.servlet.api)
    // Jakarta 变体生成的类要能被加载（加载后才能断言字段）
    testImplementation(libs.jakarta.servlet.api)
    testImplementation(project(":tools:godzilla"))
    testImplementation(libs.okhttp3)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
