plugins {
    id("java")
    id("application")
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

