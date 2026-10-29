plugins {
    id("java-library")
    alias(libs.plugins.lombok)
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Java deserialize payload for MemShellParty"
version = rootProject.version

sourceSets {
    create("fixtures")
}

dependencies {
    api(project(":memshell-party-api"))
    implementation(project(":memshell-party-common"))
    testImplementation(sourceSets["fixtures"].output)
    implementation(project(":memshell-party-fileless"))
    compileOnly(libs.metainf.services)
    annotationProcessor(libs.metainf.services)
    implementation(libs.bcel)
    implementation(libs.bundles.jna)
    implementation("com.caucho:hessian:4.0.66")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    implementation("commons-collections:commons-collections:3.2.1")
    implementation("org.apache.commons:commons-collections4:4.0")
    testImplementation(libs.junit.jupiter)
    testImplementation(project(":memshell-party-core"))
    testImplementation(libs.groovy)
    // 仅测试用 JSON 解析校验手写载荷；运行期不再依赖 jackson-databind
    testImplementation(libs.jackson.databind)
    testImplementation("com.h2database:h2:1.4.200")
    testRuntimeOnly(libs.junit.platform.launcher)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.named<JavaCompile>("compileFixturesJava") {
    sourceCompatibility = "6"
    targetCompatibility = "6"
}

tasks.test {
    useJUnitPlatform {
        excludeTags("no-jna")
    }
}

/**
 * 模拟下游 exclude 掉 JNA 后的运行时：同一份测试类，只把 jna / jna-platform jar 从
 * 类路径里摘掉。注册表必须照常初始化，只跳过依赖 JNA 的 AgentJar 附加器。
 */
val noJnaTest by tasks.registering(Test::class) {
    description = "Run packer registry tests without JNA on the classpath"
    group = "verification"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath.filter {
        !it.name.startsWith("jna-") && !it.name.startsWith("jna-platform-")
    }
    useJUnitPlatform {
        includeTags("no-jna")
    }
}

tasks.check {
    dependsOn(noJnaTest)
}

tasks.register<JavaExec>("windowsPackedFixtureJar") {
    group = "verification"
    description = "Builds the real packed-bootstrap Windows retransformation fixture."
    dependsOn("testClasses", ":memshell-party-fileless:nativeFixtureJar")
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("com.reajason.javaweb.packer.jar.agent.WindowsPackedFixtureGenerator")
    args(
        project(":memshell-party-fileless").layout.buildDirectory.file("verification/native-fileless-fixture.jar").get().asFile,
        layout.buildDirectory.file("verification/windows-packed-fileless-fixture.jar").get().asFile
    )
}