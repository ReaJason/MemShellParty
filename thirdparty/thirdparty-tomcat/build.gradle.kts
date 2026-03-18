plugins {
    id("java-library")
    id("maven-publish-convention")
}

group = "com.reajason.javaweb"
description = "thirdparty simple class"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation(libs.javax.servlet.api)
}