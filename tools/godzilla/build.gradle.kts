plugins {
    id("java")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}


dependencies {
    implementation(project(":memshell-party-common"))
    implementation(libs.java.websocket)
    implementation(libs.javax.servlet.api)
    implementation(libs.okhttp3)
    implementation(libs.fastjson2)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}