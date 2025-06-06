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
    implementation("net.bytebuddy:byte-buddy:1.17.5")
}

tasks.jar {
    manifest {
        attributes("Premain-Class" to "com.reajason.javaweb.memshell.agent.CommandFilterChainTransformer")
        attributes("Agent-Class" to "com.reajason.javaweb.memshell.agent.CommandFilterChainTransformer")
        attributes("Can-Redefine-Classes" to true)
        attributes("Can-Retransform-Classes" to true)
        attributes("Can-Set-Native-Method-Prefix" to true)
    }

    finalizedBy(tasks.shadowJar)
}