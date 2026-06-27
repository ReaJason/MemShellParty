plugins {
    id("java")
    id("idea")
}

group = "io.github.reajason"
version = rootProject.version

val dubboProviderCommon: SourceSet by sourceSets.creating
val dubboProviderAlibaba: SourceSet by sourceSets.creating
val dubboProviderApache276: SourceSet by sourceSets.creating
val dubboProviderApache277: SourceSet by sourceSets.creating
val dubboProviderApache278: SourceSet by sourceSets.creating
val dubboProviderApache2723: SourceSet by sourceSets.creating
val dubboProviderApache336: SourceSet by sourceSets.creating

val dubboProviderCommonImplementation: Configuration by configurations.getting
val dubboProviderAlibabaImplementation: Configuration by configurations.getting
val dubboProviderApache276Implementation: Configuration by configurations.getting
val dubboProviderApache277Implementation: Configuration by configurations.getting
val dubboProviderApache278Implementation: Configuration by configurations.getting
val dubboProviderApache2723Implementation: Configuration by configurations.getting
val dubboProviderApache336Implementation: Configuration by configurations.getting

val dubboProviderCommonOutput = dubboProviderCommon.output

dubboProviderAlibaba.compileClasspath += dubboProviderCommonOutput
dubboProviderAlibaba.runtimeClasspath += dubboProviderCommonOutput
dubboProviderApache276.compileClasspath += dubboProviderCommonOutput
dubboProviderApache276.runtimeClasspath += dubboProviderCommonOutput
dubboProviderApache277.compileClasspath += dubboProviderCommonOutput
dubboProviderApache277.runtimeClasspath += dubboProviderCommonOutput
dubboProviderApache278.compileClasspath += dubboProviderCommonOutput
dubboProviderApache278.runtimeClasspath += dubboProviderCommonOutput
dubboProviderApache2723.compileClasspath += dubboProviderCommonOutput
dubboProviderApache2723.runtimeClasspath += dubboProviderCommonOutput
dubboProviderApache336.compileClasspath += dubboProviderCommonOutput
dubboProviderApache336.runtimeClasspath += dubboProviderCommonOutput

listOf(
    "dubboProviderApache336CompileClasspath",
    "dubboProviderApache336RuntimeClasspath"
).forEach { configurationName ->
    configurations.named(configurationName) {
        exclude(group = "io.netty", module = "netty-transport-native-kqueue")
        exclude(group = "io.netty", module = "netty-resolver-dns-native-macos")
    }
}

idea {
    module {
        excludeDirs.add(file("src/main"))
    }
}

dependencies {
    dubboProviderCommonImplementation("org.slf4j:slf4j-api:1.7.36")
    dubboProviderCommonImplementation("org.apache.dubbo:dubbo:2.7.23") {
        exclude(group = "log4j", module = "log4j")
    }

    dubboProviderAlibabaImplementation(dubboProviderCommonOutput)
    dubboProviderAlibabaImplementation("com.alibaba:dubbo:2.6.12")
    dubboProviderAlibabaImplementation("org.apache.dubbo:dubbo:2.7.6")
    dubboProviderAlibabaImplementation("com.alibaba:hessian-lite:3.2.4")
    dubboProviderAlibabaImplementation("com.caucho:hessian:4.0.51")
    dubboProviderAlibabaImplementation("org.apache.httpcomponents:httpclient:4.5.3")
    dubboProviderAlibabaImplementation("org.springframework:spring-web:5.3.39")
    dubboProviderAlibabaImplementation("io.netty:netty-all:4.1.25.Final")
    dubboProviderAlibabaImplementation("org.mortbay.jetty:jetty:6.1.26")
    dubboProviderAlibabaImplementation("org.mortbay.jetty:jetty-util:6.1.26")
    dubboProviderAlibabaImplementation("org.slf4j:slf4j-api:1.7.36")
    dubboProviderAlibabaImplementation("ch.qos.logback:logback-classic:1.2.13")

    fun apacheDubbo27Provider(configuration: Configuration, version: String, tomcatVersion: String) {
        add(configuration.name, dubboProviderCommonOutput)
        add(configuration.name, "org.apache.dubbo:dubbo:$version") {
            exclude(group = "log4j", module = "log4j")
        }
        add(configuration.name, "com.alibaba:hessian-lite:3.2.4")
        add(configuration.name, "com.caucho:hessian:4.0.51")
        add(configuration.name, "org.apache.httpcomponents:httpclient:4.5.13")
        add(configuration.name, "com.github.briandilley.jsonrpc4j:jsonrpc4j:1.2.0")
        add(configuration.name, "org.springframework:spring-web:5.3.39")
        add(configuration.name, "org.apache.tomcat.embed:tomcat-embed-core:$tomcatVersion")
        add(configuration.name, "org.mortbay.jetty:jetty:6.1.26")
        add(configuration.name, "org.mortbay.jetty:jetty-util:6.1.26")
        add(configuration.name, "org.slf4j:slf4j-api:1.7.36")
        add(configuration.name, "ch.qos.logback:logback-classic:1.2.13")
    }

    apacheDubbo27Provider(dubboProviderApache276Implementation, "2.7.6", "8.5.100")
    apacheDubbo27Provider(dubboProviderApache277Implementation, "2.7.7", "8.5.100")
    apacheDubbo27Provider(dubboProviderApache278Implementation, "2.7.8", "9.0.104")
    apacheDubbo27Provider(dubboProviderApache2723Implementation, "2.7.23", "9.0.104")

    dubboProviderApache336Implementation(dubboProviderCommonOutput)
    dubboProviderApache336Implementation("org.apache.dubbo:dubbo:3.3.6") {
        exclude(group = "log4j", module = "log4j")
    }
    dubboProviderApache336Implementation("org.apache.dubbo:dubbo-rpc-triple:3.3.6")
    dubboProviderApache336Implementation("org.apache.dubbo.extensions:dubbo-rpc-http:3.3.1")
    dubboProviderApache336Implementation("org.apache.dubbo.extensions:dubbo-rpc-hessian:3.3.0")
    dubboProviderApache336Implementation("org.apache.dubbo:dubbo-remoting-http:3.3.0-beta.2")
    dubboProviderApache336Implementation("com.caucho:hessian:4.0.51")
    dubboProviderApache336Implementation("io.netty:netty-all:4.1.119.Final")
    dubboProviderApache336Implementation("org.slf4j:slf4j-api:2.0.17")
    dubboProviderApache336Implementation("ch.qos.logback:logback-classic:1.5.18")
}

tasks.named<JavaCompile>(dubboProviderCommon.compileJavaTaskName) {
    options.release.set(8)
}

listOf(
    dubboProviderAlibaba,
    dubboProviderApache276,
    dubboProviderApache277,
    dubboProviderApache278,
    dubboProviderApache2723,
    dubboProviderApache336
).forEach { sourceSet ->
    tasks.named<JavaCompile>(sourceSet.compileJavaTaskName) {
        options.release.set(8)
    }
}

fun registerDubboFatJar(
    taskName: String,
    sourceSet: SourceSet,
    mainClassName: String,
    mergeApacheProtocolSpi: Boolean = false
): TaskProvider<Jar> {
    val protocolSpiPath = "META-INF/dubbo/internal/org.apache.dubbo.rpc.Protocol"
    val mergedProtocolSpi = layout.buildDirectory.file("generated/$taskName/$protocolSpiPath")
    val mergeTask = if (mergeApacheProtocolSpi) {
        tasks.register("${taskName}MergeProtocolSpi") {
            inputs.files(sourceSet.runtimeClasspath)
            outputs.file(mergedProtocolSpi)
            doLast {
                val outputFile = mergedProtocolSpi.get().asFile
                outputFile.parentFile.mkdirs()
                val mergedLines = linkedSetOf<String>()
                sourceSet.runtimeClasspath.files
                    .filter { it.extension == "jar" }
                    .forEach { runtimeJar ->
                        zipTree(runtimeJar).matching {
                            include(protocolSpiPath)
                        }.forEach { spiFile ->
                            spiFile.readLines()
                                .map(String::trim)
                                .filter { it.isNotEmpty() && !it.startsWith("#") }
                                .forEach(mergedLines::add)
                        }
                    }
                outputFile.writeText(mergedLines.joinToString(System.lineSeparator()))
            }
        }
    } else {
        null
    }

    return tasks.register<Jar>(taskName) {
        group = "verification"
        archiveClassifier.set(taskName.removePrefix("dubbo").removeSuffix("FatJar").lowercase())
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
        dependsOn(sourceSet.classesTaskName, dubboProviderCommon.classesTaskName)
        manifest {
            attributes["Main-Class"] = mainClassName
        }
        from(sourceSet.output)
        from(dubboProviderCommon.output)
        if (mergeApacheProtocolSpi) {
            dependsOn(mergeTask)
            from({
                sourceSet.runtimeClasspath.files
                    .filter { it.exists() }
                    .map { if (it.isDirectory) it else zipTree(it) }
            }) {
                includeEmptyDirs = false
                exclude(protocolSpiPath)
            }
            into("META-INF/dubbo/internal") {
                from(mergedProtocolSpi) {
                    rename { "org.apache.dubbo.rpc.Protocol" }
                }
            }
        } else {
            from({
                sourceSet.runtimeClasspath.files
                    .filter { it.exists() }
                    .map { if (it.isDirectory) it else zipTree(it) }
            })
        }
    }
}

val dubboAlibabaProviderFatJar = registerDubboFatJar(
    "dubboAlibabaProviderFatJar",
    dubboProviderAlibaba,
    "io.github.reajason.dubbo.fixture.alibaba.AlibabaDubbo2Provider"
)
val dubboApache276ProviderFatJar = registerDubboFatJar(
    "dubboApache276ProviderFatJar",
    dubboProviderApache276,
    "io.github.reajason.dubbo.fixture.apache2.ApacheDubbo276Provider"
)
val dubboApache277ProviderFatJar = registerDubboFatJar(
    "dubboApache277ProviderFatJar",
    dubboProviderApache277,
    "io.github.reajason.dubbo.fixture.apache2.ApacheDubbo277Provider"
)
val dubboApache278ProviderFatJar = registerDubboFatJar(
    "dubboApache278ProviderFatJar",
    dubboProviderApache278,
    "io.github.reajason.dubbo.fixture.apache2.ApacheDubbo278Provider"
)
val dubboApache2723ProviderFatJar = registerDubboFatJar(
    "dubboApache2723ProviderFatJar",
    dubboProviderApache2723,
    "io.github.reajason.dubbo.fixture.apache2.ApacheDubbo2723Provider"
)
val dubboApache336ProviderFatJar = registerDubboFatJar(
    "dubboApache336ProviderFatJar",
    dubboProviderApache336,
    "io.github.reajason.dubbo.fixture.apache3.ApacheDubbo336Provider",
    mergeApacheProtocolSpi = true
)

tasks.register("dubboProviderFatJars") {
    group = "verification"
    dependsOn(
        dubboAlibabaProviderFatJar,
        dubboApache276ProviderFatJar,
        dubboApache277ProviderFatJar,
        dubboApache278ProviderFatJar,
        dubboApache2723ProviderFatJar,
        dubboApache336ProviderFatJar
    )
}
