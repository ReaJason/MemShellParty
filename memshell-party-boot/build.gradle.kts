plugins {
    id("java")
    id("org.springframework.boot") version "4.1.0"
    id("io.spring.dependency-management") version "1.1.7"
    alias(libs.plugins.lombok)
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
    implementation(project(":memshell-party-core"))
    // boot 内嵌真 Tomcat（starter-web），而 stub-tomcat 与 tomcat-embed-core 同包名，
    // 一旦落到运行期类路径就会遮蔽 org.apache.coyote.Adapter 等类（Connector 初始化报
    // NoSuchMethodError: Adapter.getDomain()）；Tomcat 模板父链改由真 Tomcat 提供
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
