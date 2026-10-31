plugins {
    id("java")
    alias(libs.plugins.shadow)
}

group = "com.reajason.javaweb"
version = "1.0.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_6
    targetCompatibility = JavaVersion.VERSION_1_6
}

dependencies {
    implementation(libs.bundles.jna)
}

tasks.jar {
    manifest {
        attributes("Premain-Class" to "Agent")
        attributes("Agent-Class" to "Agent")
        attributes("Main-Class" to "Main")
        attributes("Can-Redefine-Classes" to true)
        attributes("Can-Retransform-Classes" to true)
        attributes("Can-Set-Native-Method-Prefix" to true)
    }
    finalizedBy(tasks.shadowJar)
}
