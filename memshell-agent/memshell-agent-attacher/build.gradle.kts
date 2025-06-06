plugins {
    id("java")
    id("com.gradleup.shadow") version "8.3.6"
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
    implementation("net.java.dev.jna:jna:5.17.0")
    implementation("net.java.dev.jna:jna-platform:5.17.0")
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

