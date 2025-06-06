plugins {
    id("java")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

dependencies {
    implementation(platform(project(":memshell-party-bom")))
    testImplementation(project(":vul:vul-webapp"))
    testImplementation(project(":memshell-party-common"))
    testImplementation(project(":tools:behinder"))
    testImplementation(project(":tools:godzilla"))
    testImplementation(project(":tools:suo5"))
    testImplementation(project(":tools:ant-sword"))
    testImplementation(project(":generator"))
    testImplementation("net.bytebuddy:byte-buddy")
    testImplementation("javax.servlet:javax.servlet-api")
    testImplementation("javax.websocket:javax.websocket-api")
    testImplementation("org.java-websocket:Java-WebSocket")
    testImplementation("com.squareup.okhttp3:okhttp")
    testImplementation("org.slf4j:slf4j-simple:2.0.16")
    testImplementation(platform("org.junit:junit-bom"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit.platform:junit-platform-reporting")
    testImplementation("org.hamcrest:hamcrest")
    testImplementation("org.testcontainers:testcontainers")
    testImplementation("org.testcontainers:junit-jupiter")
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