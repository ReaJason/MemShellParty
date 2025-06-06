plugins {
    id("org.springframework.boot") version "2.7.6"
    id("io.spring.dependency-management") version "1.0.15.RELEASE"
    id("java")
    id("war")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web") {
        exclude(module = "spring-boot-starter-tomcat")
    }
    implementation("commons-io:commons-io:2.19.0")
    implementation("net.bytebuddy:byte-buddy:1.10.10")
    implementation("org.springframework.boot:spring-boot-starter-jetty")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.test {
    useJUnitPlatform()
}
