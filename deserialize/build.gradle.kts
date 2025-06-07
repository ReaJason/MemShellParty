plugins {
    id("java")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Java deserialize payload for MemShellParty"
version = rootProject.version

dependencies {
    implementation(platform(project(":memshell-party-bom")))
    implementation(project(":memshell-party-common"))
    implementation("net.bytebuddy:byte-buddy")
    implementation("com.caucho:hessian:4.0.66")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    implementation("commons-collections:commons-collections:3.2.1")
    implementation("org.apache.commons:commons-collections4:4.0")
    testImplementation(platform("org.junit:junit-bom"))
    testImplementation("org.junit.jupiter:junit-jupiter")
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