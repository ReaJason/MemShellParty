import org.gradle.api.plugins.JavaPlugin

plugins {
    id("java")
    id("idea")
}

group = "io.github.reajason"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
}

val dubboClientClasspathDir = layout.buildDirectory.dir("dubbo-client-classpaths")

val dubboClientCommon: SourceSet by sourceSets.creating
val dubboClientAlibaba: SourceSet by sourceSets.creating
val dubboClientApache: SourceSet by sourceSets.creating

val dubboClientCommonImplementation: Configuration by configurations.getting
val dubboClientAlibabaImplementation: Configuration by configurations.getting
val dubboClientApacheImplementation: Configuration by configurations.getting

val dubboClientCommonOutput = dubboClientCommon.output

dubboClientAlibaba.compileClasspath += dubboClientCommonOutput
dubboClientAlibaba.runtimeClasspath += dubboClientCommonOutput
dubboClientApache.compileClasspath += dubboClientCommonOutput
dubboClientApache.runtimeClasspath += dubboClientCommonOutput

idea {
    module {
        excludeDirs.add(file("src/main"))
    }
}

dependencies {
    dubboClientCommonImplementation("org.slf4j:slf4j-api:1.7.36")

    dubboClientAlibabaImplementation(dubboClientCommonOutput)
    dubboClientAlibabaImplementation("com.alibaba:dubbo:2.6.12")
    dubboClientAlibabaImplementation("com.alibaba:hessian-lite:3.2.4")
    dubboClientAlibabaImplementation("com.caucho:hessian:4.0.51")
    dubboClientAlibabaImplementation("org.apache.httpcomponents:httpclient:4.5.3")
    dubboClientAlibabaImplementation("org.springframework:spring-web:5.3.39")
    dubboClientAlibabaImplementation("io.netty:netty-all:4.1.25.Final")
    dubboClientAlibabaImplementation("org.mortbay.jetty:jetty:6.1.26")
    dubboClientAlibabaImplementation("org.mortbay.jetty:jetty-util:6.1.26")
    dubboClientAlibabaImplementation("org.slf4j:slf4j-api:1.7.36")
    dubboClientAlibabaImplementation("ch.qos.logback:logback-classic:1.2.13")

    dubboClientApacheImplementation(dubboClientCommonOutput)
    dubboClientApacheImplementation("org.apache.dubbo:dubbo:3.3.6") {
        exclude(group = "log4j", module = "log4j")
        exclude(group = "io.netty", module = "netty-transport-native-kqueue")
        exclude(group = "io.netty", module = "netty-resolver-dns-native-macos")
    }
    dubboClientApacheImplementation("org.apache.dubbo:dubbo-rpc-triple:3.3.6")
    dubboClientApacheImplementation("org.apache.dubbo.extensions:dubbo-rpc-http:3.3.1")
    dubboClientApacheImplementation("org.apache.dubbo.extensions:dubbo-rpc-hessian:3.3.0")
    dubboClientApacheImplementation("org.apache.dubbo:dubbo-remoting-http:3.3.0-beta.2")
    dubboClientApacheImplementation("com.caucho:hessian:4.0.51")
    dubboClientApacheImplementation("io.netty:netty-all:4.1.119.Final") {
        exclude(group = "io.netty", module = "netty-transport-native-kqueue")
        exclude(group = "io.netty", module = "netty-resolver-dns-native-macos")
    }
    dubboClientApacheImplementation("org.slf4j:slf4j-api:2.0.17")
    dubboClientApacheImplementation("ch.qos.logback:logback-classic:1.5.18")
}

tasks.register("dubboClientClasspath") {
    group = "verification"
    description = "Writes the isolated Alibaba and Apache Dubbo runtime classpaths"
    val alibabaRuntime = dubboClientAlibaba.runtimeClasspath
    val apacheRuntime = dubboClientApache.runtimeClasspath
    val alibabaFile = dubboClientClasspathDir.map { it.file("alibaba.txt") }
    val apacheFile = dubboClientClasspathDir.map { it.file("apache.txt") }
    inputs.files(alibabaRuntime, apacheRuntime)
    outputs.files(alibabaFile, apacheFile)
    doLast {
        alibabaFile.get().asFile.apply {
            parentFile.mkdirs()
            writeText(alibabaRuntime.asPath)
        }
        apacheFile.get().asFile.apply {
            parentFile.mkdirs()
            writeText(apacheRuntime.asPath)
        }
    }
}

tasks.named(JavaPlugin.CLASSES_TASK_NAME) {
    dependsOn(dubboClientCommon.classesTaskName, dubboClientAlibaba.classesTaskName, dubboClientApache.classesTaskName)
}
