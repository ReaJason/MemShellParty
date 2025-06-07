plugins {
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("commons-fileupload:commons-fileupload:1.5")
    implementation("commons-beanutils:commons-beanutils:1.9.3")
    providedCompile("jakarta.servlet:jakarta.servlet-api:5.0.0")
}