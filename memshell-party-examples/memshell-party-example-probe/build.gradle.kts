plugins {
    id("java")
}

group = "io.github.reajason"
description = "Example: generate probe shells (回显马) to fingerprint the target environment"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // 回显马生成引擎（ProbeShellGenerator / ProbeConfig / 各 payload 模板）全在 core 里，
    // 不依赖任何 server 模块：ResponseBody/Sleep 的 writer 模板按 server 名字从 core 的 payload 表里选
    implementation(project(":memshell-party-core"))
    // 生成结果随手打包（JSP / EL / 脚本引擎……）需要 packer
    implementation(project(":memshell-party-packer"))

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
