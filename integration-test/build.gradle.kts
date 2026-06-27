plugins {
    id("java")
    id("idea")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

evaluationDependsOn(":vul:vul-dubbo")
evaluationDependsOn(":tools:command")

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
    testImplementation(project(":generator"))
    testImplementation(project(":packer"))
    testImplementation(libs.javax.servlet.api)
    testImplementation(libs.javax.websocket.api)
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

fun dubboProviderJar(taskName: String): Provider<String> {
    return dubboProviderProject.tasks.named<Jar>(taskName).flatMap { task ->
        task.archiveFile.map { it.asFile.absolutePath }
    }
}

fun dubboClientClasspath(clientKind: String): Provider<String> {
    return dubboCommandProject.layout.buildDirectory.file("dubbo-client-classpaths/$clientKind.txt").map {
        it.asFile.readText()
    }
}

fun Test.configureDubboSystemProperties() {
    dependsOn(":vul:vul-dubbo:dubboProviderFatJars", ":tools:command:dubboClientClasspath")
    val systemProperties = mapOf(
        "dubbo.alibaba.client.classpath" to dubboClientClasspath("alibaba"),
        "dubbo.apache.client.classpath" to dubboClientClasspath("apache"),
        "dubbo.alibaba.provider.jar" to dubboProviderJar("dubboAlibabaProviderFatJar"),
        "dubbo.apache276.provider.jar" to dubboProviderJar("dubboApache276ProviderFatJar"),
        "dubbo.apache277.provider.jar" to dubboProviderJar("dubboApache277ProviderFatJar"),
        "dubbo.apache278.provider.jar" to dubboProviderJar("dubboApache278ProviderFatJar"),
        "dubbo.apache2723.provider.jar" to dubboProviderJar("dubboApache2723ProviderFatJar"),
        "dubbo.apache336.provider.jar" to dubboProviderJar("dubboApache336ProviderFatJar")
    )
    doFirst {
        systemProperties.forEach { (key, value) ->
            systemProperty(key, value.get())
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
    dependsOn("testClasses")
    configureDubboSystemProperties()
    configureIntegrationJvm()
}
