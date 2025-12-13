plugins {
    id("java")
    id("org.springframework.boot") version "3.5.8"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "io.github.reajason"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.processResources { filesMatching("**/application.yaml") { expand(project.properties) } }

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

extra["byte-buddy.version"] = libs.versions.byte.buddy.get()

dependencies {
    implementation(project(":generator")) {
        exclude(group = "commons-logging", module = "commons-logging")
    }
    implementation(project(":packer")) {
        exclude(group = "commons-logging", module = "commons-logging")
    }
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-web") {
        exclude(group = "org.springframework.boot", module = "spring-boot-starter-tomcat")
    }
    implementation(libs.commons.lang3)
    implementation("org.springframework.boot:spring-boot-starter-undertow")
    compileOnly("org.projectlombok:lombok")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    annotationProcessor("org.projectlombok:lombok")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
