plugins {
    id("java")
    id("idea")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

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
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.hamcrest)
    testImplementation(libs.bundles.testcontainers)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs(
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED"
    )
    testLogging {
        events("passed", "skipped", "failed")
    }
}