plugins {
    id("java")
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.lombok)
}

group = "io.github.reajason"
version = rootProject.version

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

// The only template value is ${version}; capturing just that string keeps the
// processResources action free of script/project references under the configuration cache.
tasks.processResources {
    val resourceVersion = project.version.toString()
    inputs.property("templateVersion", resourceVersion)
    filesMatching("**/application.yaml") {
        expand("version" to resourceVersion)
    }
}

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

dependencies {
    val springBootBom = platform(libs.spring.boot.dependencies)
    // annotationProcessor/developmentOnly do not extend implementation, so each needs the BOM.
    implementation(springBootBom)
    annotationProcessor(springBootBom)
    developmentOnly(springBootBom)
    // Pin the generator's Byte Buddy explicitly instead of relying on the Boot-managed version.
    implementation(libs.byte.buddy)
    implementation(project(":memshell-party-core"))
    implementation(project(":memshell-party-server:memshell-party-server-all")) {
        exclude(group = "io.github.reajason", module = "memshell-party-stub-tomcat")
    }
    implementation(project(":memshell-party-shelltool:memshell-party-shelltool-all"))
    implementation(project(":memshell-party-packer"))
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation(platform(libs.spring.ai.bom))
    implementation(libs.spring.ai.starter.mcp.server.webmvc)
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
