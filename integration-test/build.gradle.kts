plugins {
    id("java")
    id("idea")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

idea {
    module {
        excludeDirs.add(file("src/main"))
    }
}

dependencies {
    testImplementation(project(":memshell-party-common"))
    testImplementation(project(":tools:behinder"))
    testImplementation(project(":tools:godzilla"))
    testImplementation(project(":tools:suo5"))
    testImplementation(project(":tools:ant-sword"))
    testImplementation(project(":memshell-party-core"))
    testImplementation(project(":memshell-party-server:memshell-party-server-all"))
    testImplementation(project(":memshell-party-shelltool:memshell-party-shelltool-all"))
    testImplementation(project(":memshell-party-packer"))
    // CVE-2016-4437（Shiro-550）验收要调 exploit 模块的 SDK（探测/爆破/装载器注入编排）
    testImplementation(project(":memshell-party-gui:memshell-party-gui-shiro-exploit"))
    // 生成期的模板父类签名 jar（servlet/websocket/tomcat-embed/spring/dubbo/jetty-stub…）
    // 由各 server 模块以 implementation 自带，随 server-all 传递下来，无需在此显式声明
    testImplementation(libs.netty.all)
    testImplementation(libs.java.websocket)
    testImplementation(libs.okhttp3)
    testImplementation(libs.junit.platform.reporting)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.junit.pioneer)
    testImplementation(libs.logback.classic)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.hamcrest)
    testImplementation(libs.bundles.testcontainers) {
        exclude(group = "net.java.dev.jna", module = "jna")
    }
}

val dubboProviderProject = project(":vul:vul-dubbo")
val dubboCommandProject = project(":tools:command")

// Shiro 验收（§6.3 F22-B）的构造器标记 fixture：目标容器是 JDK 8u102，class 版本必须 ≤52，
// 而 test 源码集跟随 Gradle 守护进程 JVM（17+）出 61——所以 fixture 走独立编译任务出 8 字节码。
// 不进 test 源码集：测试 JVM 只按资源读字节，绝不加载/实例化它（构造器会在本机写标记文件）。
val compileShiroExploitFixtures = tasks.register<JavaCompile>("compileShiroExploitFixtures") {
    group = "build"
    description = "Compiles the Shiro constructor-marker fixture with Java 8 bytecode"
    source = fileTree("src/shiro-fixtures/java")
    classpath = files()
    destinationDirectory.set(layout.buildDirectory.dir("shiro-fixtures/classes"))
    options.release.set(8)
}

sourceSets.test {
    runtimeClasspath += files(compileShiroExploitFixtures.flatMap { it.destinationDirectory })
}

fun dubboProviderJar(taskName: String): Provider<RegularFile> {
    return dubboProviderProject.tasks.named<Jar>(taskName).flatMap { it.archiveFile }
}

fun dubboClientClasspath(clientKind: String): Provider<RegularFile> {
    return dubboCommandProject.layout.buildDirectory.file("dubbo-client-classpaths/$clientKind.txt")
}

fun Test.configureDubboSystemProperties(
    clientClasspathTask: TaskProvider<*>,
    providerFatJarsTask: TaskProvider<*>,
    providerJars: Map<String, Provider<RegularFile>>
) {
    val clientClasspaths = mapOf(
        "dubbo.alibaba.client.classpath" to dubboClientClasspath("alibaba"),
        "dubbo.apache.client.classpath" to dubboClientClasspath("apache")
    )
    // Ordering comes from dependsOn; only file providers go into inputs. Passing the
    // TaskProvider itself to inputs.files makes Gradle serialize the task object.
    dependsOn(clientClasspathTask, providerFatJarsTask)
    inputs.files(clientClasspaths.values, providerJars.values)
    doFirst {
        clientClasspaths.forEach { (key, file) ->
            systemProperty(key, file.get().asFile.readText())
        }
        providerJars.forEach { (key, jar) ->
            systemProperty(key, jar.get().asFile.absolutePath)
        }
    }
}

// The Dubbo fixture tasks are registered by two other projects' scripts, so wire their
// outputs as inputs only after every project has been configured.
gradle.projectsEvaluated {
    val clientClasspathTask = dubboCommandProject.tasks.named("dubboClientClasspath")
    val providerFatJarsTask = dubboProviderProject.tasks.named("dubboProviderFatJars")
    val providerJars = mapOf(
        "dubbo.alibaba.provider.jar" to dubboProviderJar("dubboAlibabaProviderFatJar"),
        "dubbo.apache276.provider.jar" to dubboProviderJar("dubboApache276ProviderFatJar"),
        "dubbo.apache277.provider.jar" to dubboProviderJar("dubboApache277ProviderFatJar"),
        "dubbo.apache278.provider.jar" to dubboProviderJar("dubboApache278ProviderFatJar"),
        "dubbo.apache2723.provider.jar" to dubboProviderJar("dubboApache2723ProviderFatJar"),
        "dubbo.apache336.provider.jar" to dubboProviderJar("dubboApache336ProviderFatJar")
    )
    tasks.withType<Test>().configureEach {
        if (name == "test" || name == "dubboContainerTest") {
            configureDubboSystemProperties(clientClasspathTask, providerFatJarsTask, providerJars)
        }
    }
}

fun Test.configureIntegrationJvm() {
    jvmArgs(
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED"
    )
    testLogging {
        events("passed", "skipped", "failed")
    }
    // 类级并发度：CI 各 middleware job 按容器重量传 -PitParallelism=N（WAS 给 2，dubbo 给 1）
    val parallelism = providers.gradleProperty("itParallelism").orElse("3")
    inputs.property("itParallelism", parallelism)
    doFirst {
        systemProperty(
            "junit.jupiter.execution.parallel.config.fixed.parallelism",
            parallelism.get()
        )
    }
    // class-obf 的相对路径临时文件已由 ClassObfuscation 重定向到每次调用的独立临时目录，
    // 不依赖 CWD，也无需按 test worker 隔离工作目录。
}

tasks.test {
    useJUnitPlatform {
        excludeTags("dubbo-container")
    }
    configureIntegrationJvm()
}

tasks.register<Test>("dubboContainerTest") {
    group = "verification"
    description = "Runs DubboService provider/client integration tests."
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("dubbo-container")
    }
    configureIntegrationJvm()
}
