import org.gradle.api.file.DuplicatesStrategy
import java.util.zip.ZipFile

plugins {
    // Godzilla 插件：产物是丢进 Godzilla 的 plugin 目录（或 PluginManage 添加）的单文件 jar，
    // 因此打成 fat jar；入口类名由框架扫描规则决定（shells.plugins.<语言>.<类名>）
    id("java")
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
    // Godzilla 宿主本身是 Java 8 应用，插件类（含下发到目标的 B64Runner）保持 Java 8 字节码
    options.release.set(8)
}

dependencies {
    // Godzilla 提供 Plugin/Payload/Encoding/Swing 工具类，运行时由宿主的 CoreClassLoader 提供，
    // 打进插件反而会和宿主已有的类重复（插件类加载器 parent-first，重复也不会生效）
    compileOnly(libs.godzilla.sdk)

    // 生成链路全部复用 GUI SDK：目录（ConfigCatalogService）、表单状态（MemShellFormState）、
    // 进程内生成（GenerationService）、结果展示（ResultInfoService）
    implementation(project(":memshell-party-gui:memshell-party-gui-sdk"))
    // provider 走 SPI 发现（MemShellRegistry 里 ServiceLoader 按 TCCL 找），插件不直接编译引用，
    // 但生成时必须有：server 决定注入器模板，shelltool 决定工具 config
    runtimeOnly(project(":memshell-party-server:memshell-party-server-all"))
    runtimeOnly(project(":memshell-party-shelltool:memshell-party-shelltool-all"))

    testImplementation(libs.godzilla.sdk)
    testImplementation(project(":memshell-party-server:memshell-party-server-all"))
    testImplementation(project(":memshell-party-shelltool:memshell-party-shelltool-all"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.jar {
    // 发行物是 shadowJar（不带分类器），裸 jar 让出名字，避免两个任务写同一路径
    archiveClassifier.set("plain")
}

tasks.shadowJar {
    archiveBaseName.set("memshell-party-godzilla")
    archiveClassifier.set("")
    // 只排除 FlatLaf：Godzilla 宿主自己就是 FlatLaf 应用，插件再打一份也不会生效。
    // MigLayout/CFR 必须保留 —— 插件界面直接复用 SDK 的 MemShellGeneratorFrame（布局用 MigLayout），
    // 结果区的「查看源码」走 CFR 反编译，宿主本身不带这些依赖。
    dependencies {
        exclude(dependency("com.formdev:flatlaf:.*"))
    }
    // Shadow 默认 EXCLUDE 去重，而重复资源在进 transformer 之前就被丢掉：mergeServiceFiles
    // 每个 SPI 文件只能看到一份拷贝，合并结果只剩一条 —— 插件会只注册一个 server/工具。
    // 只对 SPI 文件放开去重，别的一律维持默认（.class 分支不经过 transformer，没有兜底手段）
    filesMatching("META-INF/services/**") {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    mergeServiceFiles()
    manifest {
        attributes(
            "Implementation-Title" to "MemShellParty Godzilla Plugin",
            "Implementation-Version" to project.version.toString(),
        )
    }
    doLast {
        // 打包后自检：Godzilla 只扫描 shells/plugins 下的类；SPI 文件必须是合并结果。
        // 合并失效时构建照样成功，坏掉的只有发行物本身（装进 Godzilla 后下拉框里只剩一个 server/工具）
        ZipFile(archiveFile.get().asFile).use { zip ->
            checkNotNull(zip.getEntry("shells/plugins/java/MemShellParty.class")) {
                "插件缺少入口类 shells/plugins/java/MemShellParty.class"
            }
            listOf("ServerProvider", "ShellToolProvider").forEach { spi ->
                val entryName = "META-INF/services/com.reajason.javaweb.memshell.spi.$spi"
                val entry = checkNotNull(zip.getEntry(entryName)) { "插件缺少 $entryName" }
                val count = zip.getInputStream(entry).bufferedReader().useLines { lines ->
                    lines.count { it.isNotBlank() }
                }
                check(count > 1) { "$entryName 只合并出 $count 条，mergeServiceFiles 没生效" }
                logger.lifecycle("$spi 合并结果：$count 个 provider")
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    // 反序列化/字节码生成需要 JDK 内部 API，与 gui-sdk 的测试同一套开关
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
