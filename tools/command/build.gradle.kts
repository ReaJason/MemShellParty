plugins {
    id("java")
    id("idea")
}

group = "io.github.reajason"
version = rootProject.version

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

listOf(
    "dubboClientApacheCompileClasspath",
    "dubboClientApacheRuntimeClasspath"
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
    }
    dubboClientApacheImplementation("org.apache.dubbo:dubbo-rpc-triple:3.3.6")
    dubboClientApacheImplementation("org.apache.dubbo.extensions:dubbo-rpc-http:3.3.1")
    dubboClientApacheImplementation("org.apache.dubbo.extensions:dubbo-rpc-hessian:3.3.0")
    dubboClientApacheImplementation("org.apache.dubbo:dubbo-remoting-http:3.3.0-beta.2")
    dubboClientApacheImplementation("com.caucho:hessian:4.0.51")
    dubboClientApacheImplementation("io.netty:netty-all:4.1.119.Final")
    dubboClientApacheImplementation("org.slf4j:slf4j-api:2.0.17")
    dubboClientApacheImplementation("ch.qos.logback:logback-classic:1.5.18")
}

tasks.named<JavaCompile>(dubboClientCommon.compileJavaTaskName) {
    options.release.set(8)
}

listOf(dubboClientAlibaba, dubboClientApache).forEach { sourceSet ->
    tasks.named<JavaCompile>(sourceSet.compileJavaTaskName) {
        options.release.set(8)
    }
}

tasks.register("dubboClientClasspath") {
    group = "verification"
    dependsOn(dubboClientAlibaba.classesTaskName, dubboClientApache.classesTaskName)
    doLast {
        layout.buildDirectory.file("dubbo-client-classpaths/alibaba.txt").get().asFile.apply {
            parentFile.mkdirs()
            writeText(dubboClientAlibaba.runtimeClasspath.asPath)
        }
        layout.buildDirectory.file("dubbo-client-classpaths/apache.txt").get().asFile.apply {
            parentFile.mkdirs()
            writeText(dubboClientApache.runtimeClasspath.asPath)
        }
    }
}

tasks.named("classes") {
    dependsOn(dubboClientCommon.classesTaskName, dubboClientAlibaba.classesTaskName, dubboClientApache.classesTaskName)
}
