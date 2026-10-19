plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "MemShellParty generation engine"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    api(project(":memshell-party-api"))
    api(libs.byte.buddy)
    implementation(libs.asm.commons)
    implementation(libs.jackson.annotations)
    implementation(libs.classobf) {
        // NOTE: class-obf is GPL-3.0 while this repository is MIT. Publishing this module to
        // Maven Central distributes a combined work; resolve licensing (isolate/replace/relicense)
        // before the next release.
        exclude(group = "org.yaml", module = "snakeyaml")
        exclude(group = "com.beust", module = "jcommander")
    }
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.hamcrest)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    // class-obf 在 CWD 读写临时文件；ClassObfuscation 已用进程内锁 + 跨进程文件锁串行化，
    // 且每次调用使用独立临时目录，无需再按 test worker 隔离工作目录。
}
