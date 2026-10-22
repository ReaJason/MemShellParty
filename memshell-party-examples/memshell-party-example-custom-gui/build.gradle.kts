import org.gradle.api.file.DuplicatesStrategy

plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    // 示例自带入口：./gradlew :memshell-party-examples:memshell-party-example-custom-gui:run
    id("application")
    // 打 fat jar（Release 发行物），同时验证下游最常踩的坑 —— SPI 文件合并（mergeServiceFiles）
    alias(libs.plugins.shadow)
}

group = "io.github.reajason"
description = "Example: custom server, shelltool and packer providers plus a desktop GUI extension via SPI"
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
    // SDK 只带界面框架，server/shelltool/packer 由下游按需自引
    api(project(":memshell-party-gui:memshell-party-gui-sdk"))
    // 内置 packer：GUI 的打包方式选择 + 演示自定义 packer 与内置项共存
    implementation(project(":memshell-party-packer"))
    // 内置 provider：演示自定义 server / shelltool 与内置项共存
    implementation(project(":memshell-party-server:memshell-party-server-tomcat"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-godzilla"))

    // 生成期依赖：自定义 shelltool 模板的父接口 javax.servlet.* 要能以字节方式解析（不会被加载进 JVM）。
    // 与内置 shelltool 模块一样用 compileOnly —— 使用方按自己打的目标类型补依赖
    compileOnly(libs.javax.servlet.api)
    // 四类 SPI 注册文件（ServerProvider/ShellToolProvider/Packer/GuiExtension）由注解处理器生成
    compileOnly(libs.metainf.services)
    annotationProcessor(libs.metainf.services)

    // 生成期验证：内置 shelltool 的工具映射与自定义 server 的注入器映射求交集
    testImplementation(project(":memshell-party-shelltool:memshell-party-shelltool-command"))
    // 同一个自定义工具在别的 servlet 容器上同样可用（这里只做生成期验证）
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

// 测试要内嵌真 Tomcat；server-tomcat 传递的桩与 tomcat-embed-core 同包名，留在测试运行时
// 会遮蔽真身（表现为 NoSuchMethodError: Adapter.getDomain() 一类）。只从测试运行时摘掉：
// 示例本身（./gradlew run）仍靠桩生成 Tomcat 的 Valve/WebSocket 等类型。
configurations.named("testRuntimeClasspath") {
    exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
}

application {
    mainClass.set("com.reajason.javaweb.examples.customgui.CustomGuiApplication")
    // 反序列化 packer 需要 JDK 内部 API（TemplatesImpl 等），JDK 9+ 需显式开放
    applicationDefaultJvmArgs = listOf(
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

tasks.jar {
    // 发行物是 shadowJar（无分类器的 memshell-party-custom-gui-<version>.jar）；
    // 裸 jar 让出默认名字，避免与 application 插件的 installDist/distZip 冲突
    archiveClassifier.set("plain")
}

tasks.shadowJar {
    // Release 发行物：双击 / java -jar 即可运行（Main-Class 由 shadow 自动取自 application.mainClass）
    archiveBaseName.set("memshell-party-custom-gui")
    archiveClassifier.set("")
    // 打包配置（filesMatching 等）不参与 up-to-date 指纹：改过配置后旧 jar 可能被当"新鲜"，
    // 而 FatJarServiceDiscoveryTest 验证的正是打包结果 —— 让 fat jar 每次都重建
    outputs.upToDateWhen { false }
    // Shadow 9 默认 EXCLUDE，且重复资源在进 transformer 之前就被丢掉：mergeServiceFiles
    // 每个 SPI 文件只能看到一份拷贝，合并结果只剩一条（下游会只发现一个工具）。
    // 只对 SPI 文件放开去重，与 memshell-party-gui-app 发行版同一套配方（FatJarServiceDiscoveryTest 验证）
    filesMatching("META-INF/services/**") {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    // 下游打包必须做的事：合并 ServerProvider / ShellToolProvider / Packer / GuiExtension
    // 四个 SPI 文件，否则插件从 fat jar 出发时不会被 ServiceLoader 发现
    mergeServiceFiles()
    manifest {
        // 与 applicationDefaultJvmArgs 等价：java -jar 场景通过 MANIFEST 的 Add-Exports/Add-Opens
        // 开放 JDK 内部 API（JDK 8 会忽略这两个属性）
        attributes(
            "Add-Exports" to "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime",
            "Add-Opens" to "java.xml/com.sun.org.apache.xalan.internal.xsltc java.base/java.util java.base/java.lang",
        )
    }
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
