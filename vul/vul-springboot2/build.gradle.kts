plugins {
    id("org.springframework.boot") version "2.7.6"
    id("io.spring.dependency-management") version "1.0.15.RELEASE"
    id("java")
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    targetCompatibility = JavaVersion.VERSION_1_8
    sourceCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("commons-io:commons-io:2.19.0")
    implementation("net.bytebuddy:byte-buddy:1.10.10")
    providedRuntime("org.springframework.boot:spring-boot-starter-tomcat")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    runtimeOnly("com.h2database:h2")
}

tasks.test {
    useJUnitPlatform()
}
