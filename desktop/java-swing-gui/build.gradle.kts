plugins {
    id("java")
    id("application")
}

group = "com.reajason.javaweb"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation(project(":generator"))
    implementation(project(":packer"))
    implementation("com.formdev:flatlaf:3.7")
    implementation("com.miglayout:miglayout-swing:5.3")

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

application {
    mainClass.set("com.reajason.javaweb.desktop.memshell.MemShellDesktopApplication")
}

tasks.test {
    useJUnitPlatform()
}
