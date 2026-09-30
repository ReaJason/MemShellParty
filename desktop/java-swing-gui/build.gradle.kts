plugins {
    id("java")
    id("application")
    alias(libs.plugins.shadow)
}

group = "com.reajason.javaweb"
version = rootProject.version

java {
    toolchain {
        // GUI 用新 JDK 启动：JDK 8 的 macOS 管线不支持 HiDPI 缩放（界面模糊），JDK 9+ 正常。
        // 要求 26+：macOS 26 (Tahoe) 上 JDK 17/21 的 Java2D 加速字形缓存在窗口启动期存在竞态，
        // 特定字形会上传为空白（如 "Tomcat" 显示成 "Tomca"，JRE 显示成 "JR"），JDK 26 已修复。
        languageVersion = JavaLanguageVersion.of(26)
    }
}

tasks.withType<JavaCompile>().configureEach {
    // 编译期校验 Java 8 API 兼容（产物仍可在 JDK 8 上运行）
    options.release.set(8)
}

tasks.processResources {
    // 把项目版本写入 classpath 资源，窗口标题运行时从 AppVersion 读取
    filesMatching("version.properties") {
        expand(mapOf("appVersion" to project.version.toString()))
    }
}

dependencies {
    implementation(project(":generator"))
    implementation(project(":packer"))
    implementation(libs.byte.buddy)
    implementation(libs.flatlaf)
    implementation(libs.miglayout.swing)
    // 结果面板「反编译」视图：从生成的类字节码还原 Java 源码
    implementation(libs.cfr)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

application {
    mainClass.set("com.reajason.javaweb.desktop.memshell.MemShellDesktopApplication")
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

tasks.shadowJar {
    // 发行物：双击 / java -jar 即可运行的全量包（Main-Class 由 shadow 自动取自 application.mainClass）
    archiveBaseName.set("memshell-party-gui")
    archiveClassifier.set("")
    mergeServiceFiles()
    manifest {
        // 与 applicationDefaultJvmArgs 等价：java -jar 场景通过 MANIFEST 的 Add-Exports/Add-Opens 开放 JDK 内部 API（JDK 8 会忽略这两个属性）
        attributes(
            "Add-Exports" to "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime",
            "Add-Opens" to "java.xml/com.sun.org.apache.xalan.internal.xsltc java.base/java.util java.base/java.lang",
        )
    }
}

tasks.test {
    useJUnitPlatform()
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

