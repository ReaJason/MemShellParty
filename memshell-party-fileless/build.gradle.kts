plugins {
    id("java-library")
    id("maven-publish-convention")
}

group = "io.github.reajason"
description = "Java 6 compatible runtime support for in-memory Agent installation"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_6
    targetCompatibility = JavaVersion.VERSION_1_6
}

sourceSets {
    create("fixtures")
}
sourceSets["fixtures"].compileClasspath += sourceSets["main"].output
sourceSets["fixtures"].runtimeClasspath += sourceSets["main"].output

dependencies {
    testImplementation(sourceSets["fixtures"].output)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.named<JavaCompile>("compileTestJava") {
    sourceCompatibility = "8"
    targetCompatibility = "8"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.register<Jar>("nativeFixtureJar") {
    group = "verification"
    description = "Builds the no-javaagent Instrumentation and retransformation fixture."
    archiveBaseName.set("native-fileless-fixture")
    archiveVersion.set("")
    destinationDirectory.set(layout.buildDirectory.dir("verification"))
    manifest {
        attributes["Main-Class"] = "com.reajason.javaweb.fileless.NativeAgentFixture"
    }
    from(sourceSets.main.get().output)
    from(sourceSets["fixtures"].output) {
        include(
            "com/reajason/javaweb/fileless/NativeAgentFixture*.class",
            "com/reajason/javaweb/fileless/WindowsNativeAgentFixture.class",
            "com/reajason/javaweb/fileless/WindowsPackedAgentFixture*.class",
            "com/reajason/javaweb/fileless/RetransformFixture.class"
        )
    }
}
