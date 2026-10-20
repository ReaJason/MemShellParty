import org.gradle.api.file.DuplicatesStrategy
import java.util.zip.ZipFile

plugins {
    // 完整发行版：SDK + 全部 server/shelltool 提供者，打成一个双击 / `java -jar` 即可运行的全量 jar。
    // 入口类在这里，UI 框架与扩展点都在 memshell-party-gui-sdk
    id("application")
    alias(libs.plugins.shadow)
}

group = "com.reajason.javaweb"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
}

dependencies {
    // 本模块只负责「装配」：把 SDK 与全量 provider 放进同一个 jar
    implementation(project(":memshell-party-gui:memshell-party-gui-sdk"))
    // 完整发行版带内置 packer；SDK 本身不再传递该依赖
    implementation(project(":memshell-party-packer"))
    implementation(project(":memshell-party-server:memshell-party-server-all"))
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-all"))
    implementation(libs.flatlaf)
    implementation(libs.flatlaf.extras)
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

tasks.jar {
    // 发行物是 shadowJar，且用无分类器的名字 memshell-party-gui-<version>.jar；裸 jar（只有入口类）
    // 让出这个名字，否则两个任务写同一个路径，application 插件的 installDist/distZip 会因
    // 「startScripts 使用了 shadowJar 的输出却没声明依赖」直接构建失败
    archiveClassifier.set("plain")
}

tasks.shadowJar {
    // 发行物：双击 / java -jar 即可运行的全量包（Main-Class 由 shadow 自动取自 application.mainClass）
    archiveBaseName.set("memshell-party-gui")
    archiveClassifier.set("")
    // Shadow 9 默认 EXCLUDE，且重复资源是在进 transformer 之前就被丢掉的：mergeServiceFiles
    // 每个 SPI 文件只能看到一份拷贝，合并结果只剩一条 —— 完整包会只注册一个 server/工具。
    // 只对 SPI 文件放开去重（回到第一条），别的一律维持默认：duplicatesStrategy 是全局的，
    // 整体改成 INCLUDE 会顺带把重复的 .class 也打进包里（.class 分支不经过 transformer，
    // 没有兜底手段）
    filesMatching("META-INF/services/**") {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    mergeServiceFiles()
    manifest {
        // 与 applicationDefaultJvmArgs 等价：java -jar 场景通过 MANIFEST 的 Add-Exports/Add-Opens 开放 JDK 内部 API（JDK 8 会忽略这两个属性）
        attributes(
            "Add-Exports" to "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime",
            "Add-Opens" to "java.xml/com.sun.org.apache.xalan.internal.xsltc java.base/java.util java.base/java.lang",
        )
    }
    doLast {
        // 打包后自检：SPI 文件必须真的是合并结果。合并失效时构建照样成功，坏掉的只有发行物本身
        // （双击运行后下拉框里只剩一个 server/工具），所以这里直接开包数条目
        ZipFile(archiveFile.get().asFile).use { zip ->
            listOf(
                "com.reajason.javaweb.memshell.spi.ServerProvider",
                "com.reajason.javaweb.memshell.spi.ShellToolProvider",
                // 完整发行版显式装配了内置 packer；SDK 本身不再传递该依赖
                "com.reajason.javaweb.packer.Packer",
            ).forEach { entryName ->
                val entry = checkNotNull(zip.getEntry("META-INF/services/$entryName")) { "全量包缺少 $entryName" }
                val count = zip.getInputStream(entry).bufferedReader().useLines { lines ->
                    lines.count { it.isNotBlank() }
                }
                check(count > 1) {
                    "$entryName 只合并出 $count 条，mergeServiceFiles 没生效：完整包会只注册一个 provider"
                }
                logger.lifecycle("$entryName 合并结果：$count 个 provider")
            }
            checkNotNull(zip.getEntry("com/reajason/javaweb/packer/base64/DefaultBase64Packer.class")) {
                "全量包缺少内置 packer 实现"
            }
        }
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
