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

// CommandExec.java 是测试中 base64 payload 类的源文件，仅作再生成参考；
// 排除在测试编译之外，避免 JUnit 扫描加载并初始化该类，导致 static 块中的 RCE 动作被提前触发
tasks.compileTestJava {
    exclude("com/reajason/javaweb/vul/springboot2/controller/CommandExec.java")
}

tasks.test {
    useJUnitPlatform()
    // vul 各模块测试并行执行时共享系统临时目录，用独立标记文件名避免互相删除
    systemProperty("memshell.vul.rce.marker", "memshell-vul-rce-proof-sb2.txt")
}
