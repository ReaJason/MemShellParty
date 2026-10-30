plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    alias(libs.plugins.shadow)
}

group = "io.github.reajason"
description = "Example external server, shellTool and packer plugin"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
}

dependencies {
    // 宿主在运行期提供 api/core；不能把它们重新打进插件，否则会产生类型身份冲突。
    compileOnly(project(":memshell-party-core"))
    compileOnly(libs.metainf.services)
    annotationProcessor(libs.metainf.services)
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.shadowJar {
    archiveBaseName.set("memshell-party-example-plugin")
    archiveClassifier.set("")
    // 额外的 implementation 第三方依赖会由 Shadow 打入；compileOnly 的宿主依赖不会。
    filesMatching("META-INF/services/**") {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }
    mergeServiceFiles()
}
