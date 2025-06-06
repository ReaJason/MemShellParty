plugins {
    id("java")
    id("org.springframework.boot") version "3.5.0"
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

dependencies {
    implementation(project(":generator")) {
        exclude(group = "org.apache.tomcat", module = "tomcat-catalina")
        exclude(group = "commons-logging", module = "commons-logging")
    }
    implementation(project(":deserialize")) {
        exclude(group = "commons-logging", module = "commons-logging")
    }
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-web") {
        exclude(group = "org.springframework.boot", module = "spring-boot-starter-tomcat")
    }
    implementation("org.apache.commons:commons-lang3:3.17.0")
    implementation("org.springframework.boot:spring-boot-starter-jetty")
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
