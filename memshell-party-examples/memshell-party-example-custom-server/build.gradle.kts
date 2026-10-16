plugins {
    id("java-library")
}

group = "io.github.reajason"
description = "Example: implement your own MemShellParty server plugin (injector) via SPI"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // 生成引擎：ServerProvider / ServerMeta / AbstractServer / InjectorMapping 都在这里
    api(project(":memshell-party-core"))

    // 生成期依赖：注入器模板引用的 javax.servlet.* 要能以字节方式解析（不会被加载进 JVM）。
    // 与内置 server 模块一样用 compileOnly —— 使用方按自己打的目标类型补依赖。
    compileOnly(libs.javax.servlet.api)
    // SPI 注册文件由注解处理器生成（@MetaInfServices）
    compileOnly(libs.metainf.services)
    annotationProcessor(libs.metainf.services)

    // 生成期验证：内置 shelltool 的工具映射与自定义 server 的注入器映射求交集
    testImplementation(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))
    testImplementation(project(":memshell-party-shelltool:memshell-party-shelltool-command"))

    // 端到端测试：内嵌 Tomcat 里从请求线程触发注入，再用 HTTP 驱动注入的内存马
    testImplementation(libs.tomcat.embed.core)
    testImplementation(libs.javax.servlet.api)
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
