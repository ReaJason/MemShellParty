plugins {
    id("java")
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}


dependencies {
    implementation(platform(project(":memshell-party-bom")))
    implementation(project(":memshell-party-common"))
    implementation("net.bytebuddy:byte-buddy")
    implementation("commons-io:commons-io")
    implementation("org.apache.commons:commons-lang3")
    implementation("commons-codec:commons-codec")
    implementation("com.squareup.okhttp3:okhttp")
    implementation("com.alibaba.fastjson2:fastjson2")
    testImplementation(platform("org.junit:junit-bom"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}