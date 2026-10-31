plugins {
    alias(libs.plugins.lombok)
    id("java8-library-conventions")
}

description = "Common Utilities for MemShellParty"

dependencies {
    api(libs.byte.buddy)
    api(libs.asm.commons)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.bundles.mockito)
}

tasks.test {
    testLogging {
        events("passed", "skipped", "failed")
    }
}