plugins {
    // 下游（自带 shelltool 的客户端）把本模块当依赖引入来写扩展，扩展点所在的 core 必须
    // 以 api 暴露给使用方编译期可见；纯 application 插件做不到这一点
    id("java-library")
    // 发布到 Maven Central：io.github.reajason:memshell-party-gui-sdk
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Extensible Swing desktop SDK of MemShellParty: extension points and generator UI, without server providers or built-in packers"
version = rootProject.version

java {
    toolchain {
        // GUI 用新 JDK 启动：JDK 8 的 macOS 管线不支持 HiDPI 缩放（界面模糊），JDK 9+ 正常。
        // 注：macOS 26 (Tahoe) + JDK<26 的整窗缺字已定位为 UI 字符串触发（拉丁段被 CJK/全角
        // 字符夹在中间渲染时污染字形缓存，见 ResultPanel 空态提示注释），字符串层面修复后
        // JDK 11/17/21 渲染均正常（JDK11 启动 5/5 验证），不再要求 26+。
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.withType<JavaCompile>().configureEach {
    // 编译期校验 Java 8 API 兼容（产物仍可在 JDK 8 上运行，下游扩展代码因此也能只依赖 Java 8）
    options.release.set(8)
}

tasks.processResources {
    // 把项目版本写入 classpath 资源，窗口标题运行时从 AppVersion 读取。
    // 版本在配置期捕获：任务动作里访问 project 会破坏配置缓存。
    val appVersion = project.version.toString()
    inputs.property("appVersion", appVersion)
    filesMatching("version.properties") {
        expand("appVersion" to appVersion)
    }
}

dependencies {
    api(project(":memshell-party-core"))
    implementation(libs.flatlaf)
    implementation(libs.miglayout.swing)
    implementation(libs.cfr)
    testImplementation(project(":memshell-party-packer"))
    testImplementation(project(":memshell-party-server:memshell-party-server-all"))
    testImplementation(project(":memshell-party-shelltool:memshell-party-shelltool-all"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    // class-obf 的相对路径临时文件已由 ClassObfuscation 重定向到每次调用的独立临时目录，
    // 不依赖 CWD，也无需按 test worker 隔离工作目录。
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
