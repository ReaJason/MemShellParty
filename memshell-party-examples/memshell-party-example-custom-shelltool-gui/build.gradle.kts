plugins {
    id("java-library")
    // 示例自带入口：./gradlew :memshell-party-examples:memshell-party-example-custom-shelltool-gui:run
    id("application")
    // 打 fat jar：验证下游最常踩的坑 —— SPI 文件合并（mergeServiceFiles）
    alias(libs.plugins.shadow)
}

group = "io.github.reajason"
description = "Example: extend the MemShellParty desktop GUI with your own ShellTool plugin"
version = rootProject.version

java {
    toolchain {
        // 与 memshell-party-gui-sdk 一致：GUI 跑在 JDK 17 上（FlatLaf/HiDPI/字形渲染）
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.withType<JavaCompile>().configureEach {
    // 编译期校验 Java 8 API 兼容：扩展代码本身可以只依赖 Java 8 API
    options.release.set(8)
}

dependencies {
    // 复用整套桌面 GUI（扩展点 GuiExtension/ToolPanelContext、面板基类、控制器、结果区）：
    // SDK 只带界面框架，server 提供者与内置 shelltool 都由下游按需自引 —— 这里只要 Tomcat + Godzilla
    api(project(":memshell-party-gui:memshell-party-gui-sdk"))
    implementation(project(":memshell-party-server:memshell-party-server-tomcat"))
    // 内置工具也是显式引入的：演示「内置 Godzilla 与自定义 GodzillaSession 共存」，
    // FatJarServiceDiscoveryTest 断言合并后的 SPI 文件里两个条目都在
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))
    // 自己的 shelltool 插件（上一个示例）：插件以 jar 形式接入，GUI 通过 SPI 发现它。
    // 用 implementation 而不是 api：这是 application，不是给别人编译用的库
    implementation(project(":memshell-party-examples:memshell-party-example-custom-shelltool"))
    // 扩展自身的 SPI 注册（@MetaInfServices → META-INF/services/...GuiExtension）
    compileOnly(libs.metainf.services)
    annotationProcessor(libs.metainf.services)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

application {
    mainClass.set("com.reajason.javaweb.examples.customshellgui.CustomShellGuiApplication")
}

tasks.shadowJar {
    archiveClassifier.set("all")
    // 打包配置（filesMatching 等）不参与 up-to-date 指纹：改过配置后旧 jar 可能被当"新鲜"，
    // 而 FatJarServiceDiscoveryTest 验证的正是打包结果 —— 让 fat jar 每次都重建
    outputs.upToDateWhen { false }
    // Shadow 9 默认 EXCLUDE，且重复资源在进 transformer 之前就被丢掉：mergeServiceFiles
    // 每个 SPI 文件只能看到一份拷贝，合并结果只剩一条（下游会只发现一个工具）。
    // 只对 SPI 文件放开去重，与 memshell-party-gui-app 发行版同一套配方（FatJarServiceDiscoveryTest 验证）
    filesMatching("META-INF/services/**") {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    // 下游打包必须做的事：合并 ShellToolProvider 与 GuiExtension 两个 SPI 文件，
    // 否则插件/扩展从 fat jar 出发时不会被 ServiceLoader 发现
    mergeServiceFiles()
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
    // fat jar 合并验证要先打 jar
    dependsOn(tasks.shadowJar)
    // 与 memshell-party-gui-sdk 的测试一致：反序列化 packer 家族要用到 JDK 内部 API
    jvmArgs(
        "--add-exports",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
        "--add-exports",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
        "--add-opens",
        "java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED",
        "--add-opens",
        "java.base/java.util=ALL-UNNAMED",
        "--add-opens",
        "java.base/java.lang=ALL-UNNAMED",
    )
}
