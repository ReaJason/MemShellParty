plugins {
    id("java")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

group = "io.github.reajason"
description = "MemShell Generator for Java"
version = rootProject.version

tasks.compileTestJava {
    javaCompiler.set(javaToolchains.compilerFor {
        languageVersion.set(JavaLanguageVersion.of(17))
    })
}

tasks.test {
    useJUnitPlatform()
}

dependencies {
    implementation(platform(project(":memshell-party-bom")))
    implementation(project(":memshell-party-common"))
    implementation(project(":deserialize"))

    implementation(project(":memshell"))
    implementation("net.bytebuddy:byte-buddy")
    implementation("org.ow2.asm:asm-commons")
    implementation("net.java.dev.jna:jna")
    implementation("net.java.dev.jna:jna-platform")
    implementation("javax.servlet:javax.servlet-api")
    implementation("javax.websocket:javax.websocket-api")
    implementation("org.apache.bcel:bcel")
    implementation("commons-io:commons-io")
    implementation("org.apache.commons:commons-lang3")
    implementation("com.squareup.okhttp3:okhttp")
    implementation("ch.qos.logback:logback-classic")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("org.springframework:spring-webmvc")
    implementation("org.springframework:spring-webflux")
    implementation("io.projectreactor.netty:reactor-netty-core")
    testImplementation(platform("org.junit:junit-bom"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")
}