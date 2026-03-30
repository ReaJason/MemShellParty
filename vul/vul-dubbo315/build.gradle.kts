plugins {
    id("org.springframework.boot") version "2.7.6"
    id("io.spring.dependency-management") version "1.0.15.RELEASE"
    id("java")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    targetCompatibility = JavaVersion.VERSION_1_8
    sourceCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.apache.dubbo:dubbo-spring-boot-starter:3.1.5")
    implementation("org.apache.dubbo.extensions:dubbo-rpc-hessian:1.0.1")
    implementation("com.caucho:hessian:4.0.66")
    implementation("javax.servlet:javax.servlet-api:4.0.1")
    implementation("org.eclipse.jetty:jetty-server")
    implementation("org.eclipse.jetty:jetty-servlet")
    implementation("commons-io:commons-io:2.19.0")
    implementation("net.bytebuddy:byte-buddy:1.10.10")
    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group = "org.mockito")
    }
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    runtimeOnly("com.h2database:h2")
}

tasks.test {
    useJUnitPlatform()
}
