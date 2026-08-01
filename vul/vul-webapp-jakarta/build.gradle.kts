plugins {
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(11)
    }
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    implementation("commons-fileupload:commons-fileupload:1.5")
    implementation("commons-beanutils:commons-beanutils:1.9.3")
    providedCompile("jakarta.servlet:jakarta.servlet-api:5.0.0")
    providedCompile("jakarta.websocket:jakarta.websocket-api:2.2.0")
    providedCompile(libs.jakarta.websocket.client.api)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
