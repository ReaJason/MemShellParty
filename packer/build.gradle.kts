plugins {
    id("java")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Java deserialize payload for MemShellParty"
version = rootProject.version

dependencies {
    implementation(project(":memshell-party-common"))
    implementation(libs.bcel)
    implementation(libs.bundles.jna)
    implementation(libs.jackson.databind)
    implementation("com.caucho:hessian:4.0.66")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    implementation("commons-collections:commons-collections:3.2.1")
    implementation("org.apache.commons:commons-collections4:4.0")
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.test {
    useJUnitPlatform()
}