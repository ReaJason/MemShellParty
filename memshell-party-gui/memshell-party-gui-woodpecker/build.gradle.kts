import org.gradle.api.file.DuplicatesStrategy
import java.util.zip.ZipFile

plugins {
    // Woodpecker 插件：产物是丢进 <woodpecker>/plugin/ 的单文件 jar，所以打成 fat jar；
    // 入口类名由框架写死（me.gv7.woodpecker.plugin.WoodpeckerPluginManager），见入口类注释
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
    // Woodpecker 宿主常见 Java 8 环境（框架 jar 也按 Java 8 编译），产物保持 Java 8 字节码
    options.release.set(8)
}

dependencies {
    // Woodpecker SDK：框架 jar 自带这些类（插件类加载器先走系统类加载器），插件里不能重复打包
    compileOnly(libs.woodpecker.sdk)

    // 生成链路全用 GUI SDK：目录（ConfigCatalogService/ProbeConfigCatalogService）、
    // 表单联动（*FormController）、校验（*Validator）、进程内生成（GenerationService）
    implementation(project(":memshell-party-gui:memshell-party-gui-sdk"))
    // 打包方式目录与打包器（Packers）直接引用，GUI SDK 里是 implementation，得自己声明
    implementation(project(":memshell-party-packer"))
    // provider 走 SPI 发现（MemShellRegistry 里 ServiceLoader 按 TCCL 找），插件不直接编译引用，
    // 但生成时必须有：server 决定模板与注入器，shelltool 决定工具 config
    runtimeOnly(project(":memshell-party-server:memshell-party-server-all"))
    runtimeOnly(project(":memshell-party-shelltool:memshell-party-shelltool-all"))

    testImplementation(libs.woodpecker.sdk)
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
    archiveBaseName.set("memshell-party-woodpecker")
    archiveClassifier.set("")
    // 只保留生成链路需要的类：GUI SDK 的界面依赖（FlatLaf/MigLayout/反编译 CFR）插件不碰，
    // 打进插件只会撑大体积（宿主自己也是 FlatLaf 应用，多一份也不生效）
    dependencies {
        exclude(dependency("com.formdev:flatlaf:.*"))
        exclude(dependency("com.miglayout:miglayout-swing:.*"))
        exclude(dependency("org.benf:cfr:.*"))
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
            "Implementation-Title" to "MemShellParty Woodpecker Plugin",
            "Implementation-Version" to project.version.toString(),
        )
    }
    doLast {
        // 打包后自检：SPI 文件必须真的是合并结果。合并失效时构建照样成功，坏掉的只有发行物本身
        //（装进 Woodpecker 后下拉框里只剩一个 server/工具），所以这里直接开包数条目
        ZipFile(archiveFile.get().asFile).use { zip ->
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
    // 反序列化打包（TemplatesImpl 等）需要 JDK 内部 API，与 gui-sdk 的测试同一套开关
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
