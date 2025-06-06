plugins {
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_6
    targetCompatibility = JavaVersion.VERSION_1_6
}

dependencies {
    implementation("commons-fileupload:commons-fileupload:1.3.3")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    providedCompile("javax.servlet:servlet-api:2.5")
}
